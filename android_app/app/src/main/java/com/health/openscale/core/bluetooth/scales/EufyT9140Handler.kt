/*
 * openScale
 * Copyright (C) 2026 openScale contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Protocol from bdr99/eufylife-ble-client (MIT, © bdr99) and particleflux's 2021
 * reverse-engineering notes; see [EufyT9140Lib] for the wire format and credits.
 * The weight path is confirmed on hardware; the history read that supplies body
 * composition is covered by EufyT9140LibTest but has not been exercised on a scale yet.
 */
package com.health.openscale.core.bluetooth.scales

import com.health.openscale.R
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.bluetooth.libs.EufyT9140Lib
import com.health.openscale.core.bluetooth.libs.OneByoneLib
import com.health.openscale.core.data.ActivityLevel
import com.health.openscale.core.data.GenderType
import com.health.openscale.core.data.Kg
import com.health.openscale.core.data.MeasurementType
import com.health.openscale.core.data.Ohm
import com.health.openscale.core.data.Percent
import com.health.openscale.core.data.WeightUnit
import com.health.openscale.core.service.ScannedDeviceInfo
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlin.math.abs

/**
 * Eufy Smart Scale T9140.
 *
 * Advertises as `eufy T9140` and speaks the older Eufy vendor profile: service `4143f6b0-…`
 * (some firmware `4143f7b0-…`, fallback `0000fff0-…`), notifications on `…b2`, writes on
 * `…b1`. No pairing and no encryption, unlike the P2/P2 Pro — see [EufyT9140Lib].
 *
 * A weigh-in arrives as a settled `AC 02 <weight> <impedance> CA` frame, with the impedance field
 * left at zero: this model finishes the BIA run after the weight settles and keeps the result in
 * its own history instead of pushing it. The driver therefore reads the history after a settle (and
 * on connect) and saves the record — weight *and* impedance — as one measurement. A weight-only
 * frame is held for [LIVE_GRACE_MS] first, so one weigh-in produces one complete row rather than a
 * weight-only row followed by a duplicate.
 *
 * Intermediate `…CE` frames while the weight is still moving are logged but not saved, because
 * openScale stores one row per weigh-in.
 */
class EufyT9140Handler : ScaleDeviceHandler() {

    private val serviceModern: UUID = UUID.fromString("4143f7b0-5300-4900-4700-414943415245")
    private val notifyModern: UUID = UUID.fromString("4143f7b2-5300-4900-4700-414943415245")
    private val writeModern: UUID = UUID.fromString("4143f7b1-5300-4900-4700-414943415245")

    private val serviceBody: UUID = UUID.fromString("4143f6b0-5300-4900-4700-414943415245")
    private val notifyBody: UUID = UUID.fromString("4143f6b2-5300-4900-4700-414943415245")
    private val writeBody: UUID = UUID.fromString("4143f6b1-5300-4900-4700-414943415245")

    private val serviceFf: UUID = uuid16(0xFFF0)
    private val notifyFf: UUID = uuid16(0xFFB2)
    private val writeFf: UUID = uuid16(0xFFB1)

    private val serviceBattery: UUID = uuid16(0x180F)
    private val charBattery: UUID = uuid16(0x2A19)

    private var service: UUID? = null
    private var notifyChar: UUID? = null
    private var writeChar: UUID? = null

    private var publishedThisSession = false

    /** Weight of a settled frame whose row is waiting for its body-composition record, or 0. */
    private var heldWeightKg = 0f
    private var heldJob: Job? = null

    /** Records already handled in this connection, by their own timestamp. */
    private val seenEpochs = mutableSetOf<Long>()

    override fun supportFor(device: ScannedDeviceInfo): DeviceSupport? {
        val name = device.name.lowercase(Locale.ROOT)
        if (!name.contains("t9140") && !name.contains("bodysense")) return null

        val caps = buildSet {
            add(DeviceCapability.LIVE_WEIGHT_STREAM)
            add(DeviceCapability.BODY_COMPOSITION)
            add(DeviceCapability.TIME_SYNC)
            add(DeviceCapability.UNIT_CONFIG)
            add(DeviceCapability.HISTORY_READ)
        }
        return DeviceSupport(
            displayName = "Eufy Smart Scale (T9140)",
            capabilities = caps,
            implemented = caps,
            tuningProfile = TuningProfile.Conservative, // Eufy firmware dislikes back-to-back writes
            linkMode = LinkMode.CONNECT_GATT
        )
    }

    override fun onConnected(user: ScaleUser) {
        // Handler instances are reused for the lifetime of the app, so reset per-connection state.
        publishedThisSession = false
        service = null
        notifyChar = null
        writeChar = null
        heldWeightKg = 0f
        heldJob?.cancel()
        heldJob = null
        seenEpochs.clear()

        val candidates = listOf(
            Triple(serviceBody, notifyBody, writeBody),
            Triple(serviceModern, notifyModern, writeModern),
            Triple(serviceFf, notifyFf, writeFf)
        )
        val found = candidates.firstOrNull { hasCharacteristic(it.first, it.second) }
            ?: candidates.firstOrNull { hasCharacteristic(it.first, it.third) }
        if (found == null) {
            logE("T9140: no known Eufy service/characteristic on this device — cannot subscribe")
            return
        }

        service = found.first
        notifyChar = found.second
        writeChar = found.third
        logI("T9140: service=${found.first} notify=${found.second} write=${found.third}")

        setNotifyOn(found.first, found.second)

        if (hasCharacteristic(serviceBattery, charBattery)) {
            setNotifyOn(serviceBattery, charBattery)
            readFrom(serviceBattery, charBattery)
        }

        // Configure the scale: unit, then clock. The characteristic is write-without-response,
        // and neither ACK is required for the weigh-in to arrive.
        writeTo(found.first, found.third, EufyT9140Lib.unitCommand(unitCode(user)), withResponse = false)
        writeTo(
            found.first,
            found.third,
            EufyT9140Lib.timeSyncCommand(System.currentTimeMillis() / 1000L),
            withResponse = false
        )

        // The impedance of a weigh-in only exists in the scale's history, so ask for it once the
        // configuration writes have gone out. Records openScale already has are filtered on arrival.
        scope.launch {
            delay(HISTORY_REQUEST_DELAY_MS)
            requestHistory()
        }

        userInfo(R.string.bt_info_step_on_scale)
    }

    override fun onNotification(characteristic: UUID, data: ByteArray, user: ScaleUser) {
        if (characteristic == charBattery) {
            val level = data.firstOrNull()?.toInt()?.and(0xFF) ?: return
            logD("T9140: battery $level%")
            if (level <= 10) userWarn(R.string.bluetooth_scale_warning_low_battery, level)
            return
        }

        // Raw dump on purpose: firmware variants put slightly different payloads in the
        // wrapper, and this line is what makes a user-submitted log diagnosable.
        logD("T9140 ← ${EufyT9140Lib.toHex(data)}")

        // History records are longer than the 16/17-byte container the live frames use, so they are
        // read before anything splits the notification.
        if (EufyT9140Lib.isHistoryStart(data)) {
            logD("T9140: history transfer started")
            return
        }
        val records = EufyT9140Lib.parseHistoryRecords(data)
        if (records.isNotEmpty()) {
            records.forEach { onHistoryRecord(it, user) }
            return
        }

        for (frame in EufyT9140Lib.splitFrames(data)) {
            onLiveFrame(frame, user)
        }
    }

    override fun onDisconnected() {
        publishedThisSession = false
        heldJob?.cancel()
        heldJob = null
        heldWeightKg = 0f
    }

    private fun requestHistory() {
        val svc = service ?: return
        val chr = writeChar ?: return
        logD("T9140 → history request")
        writeTo(svc, chr, EufyT9140Lib.historyRequestCommand(), withResponse = false)
    }

    // ── live weigh-ins ──────────────────────────────────────────────────────────

    private fun onLiveFrame(frame: ByteArray, user: ScaleUser) {
        val reading = EufyT9140Lib.parseReading(frame)
        if (reading == null) {
            logD("T9140: not a weigh-in frame (${EufyT9140Lib.toHex(frame)})")
            return
        }
        if (!reading.isFinal) {
            logD("T9140: interim ${reading.weightKg} kg")
            return
        }
        if (publishedThisSession) {
            logD("T9140: settled reading already saved this session, ignoring repeat")
            return
        }

        // Some firmware puts the BIA result straight into the settled frame; take it when it does.
        if (reading.impedanceOhm > 0) {
            heldJob?.cancel()
            heldJob = null
            heldWeightKg = 0f
            publish(buildMeasurement(reading.weightKg, reading.impedanceOhm, Date(), user))
            publishedThisSession = true
            return
        }

        // Otherwise hold the weight and give the scale a moment to store the record. If nothing
        // arrives, the weight is saved on its own — losing a weigh-in is worse than losing its body
        // composition.
        heldWeightKg = reading.weightKg
        heldJob?.cancel()
        heldJob = scope.launch {
            delay(LIVE_GRACE_MS)
            if (publishedThisSession) return@launch
            logI("T9140: no body-composition record within $LIVE_GRACE_MS ms — saving weight only")
            publish(buildMeasurement(reading.weightKg, 0, Date(), user))
            publishedThisSession = true
        }

        logD("T9140: settled ${reading.weightKg} kg, asking for history")
        scope.launch {
            delay(HISTORY_AFTER_SETTLE_DELAY_MS)
            requestHistory()
        }
    }

    // ── history records ─────────────────────────────────────────────────────────

    private fun onHistoryRecord(record: EufyT9140Lib.HistoryRecord, user: ScaleUser) {
        logI(
            "T9140: history ${Date(record.epochSeconds * 1000L)} → " +
                "${record.weightKg} kg, ${record.impedanceOhm} Ω"
        )
        if (!seenEpochs.add(record.epochSeconds)) {
            logD("T9140: history record already handled in this session")
            return
        }

        val matchesHeld = heldWeightKg > 0f && abs(record.weightKg - heldWeightKg) <= WEIGHT_TOLERANCE_KG
        if (!matchesHeld && isAlreadySaved(record, user)) {
            logD("T9140: history record matches a saved measurement, skipping")
            return
        }

        if (matchesHeld) {
            // This is the record for the weigh-in being held: one complete row, not two.
            logI("T9140: history record covers the current weigh-in — saving weight and impedance")
            heldJob?.cancel()
            heldJob = null
            heldWeightKg = 0f
            publishedThisSession = true
        }

        publish(buildMeasurement(record.weightKg, record.impedanceOhm, Date(record.epochSeconds * 1000L), user))
    }

    /**
     * True when [record] is a measurement openScale already has. Timestamps come from two clocks (the
     * phone for live rows, the scale for records), so a match is "same weight, close in time" rather
     * than an exact timestamp comparison.
     */
    private fun isAlreadySaved(record: EufyT9140Lib.HistoryRecord, user: ScaleUser): Boolean {
        val last = lastMeasurementFor(user.id) ?: return false
        val lastAt = last.dateTime?.time ?: return false
        if (record.epochSeconds * 1000L > lastAt + DUPLICATE_WINDOW_MS) return false
        val lastWeight = last[MeasurementType.WEIGHT]?.value ?: return false
        return abs(record.weightKg - lastWeight) <= WEIGHT_TOLERANCE_KG
    }

    // ── measurement assembly ────────────────────────────────────────────────────

    private fun buildMeasurement(
        weightKg: Float,
        impedanceOhm: Int,
        at: Date,
        user: ScaleUser
    ): ScaleMeasurement {
        val m = ScaleMeasurement().apply {
            userId = user.id
            dateTime = at
            this[MeasurementType.WEIGHT] = Kg(weightKg)
            // Stored even when body composition is skipped below, so it can be recomputed later.
            if (impedanceOhm > 0) {
                this[MeasurementType.IMPEDANCE] = Ohm(impedanceOhm.toFloat())
            }
        }

        if (impedanceOhm <= 0) {
            logI("T9140: no impedance for this weigh-in — saving weight only ($weightKg kg)")
            return m
        }
        if (user.bodyHeight <= 0f) {
            logI("T9140: user has no body height — saving weight and impedance only")
            return m
        }

        // Same BIA model the sibling Eufy models use (see OneByoneHandler).
        try {
            val lib = OneByoneLib(
                if (user.gender == GenderType.MALE) 1 else 0,
                user.age,
                user.bodyHeight,
                peopleType(user.activityLevel)
            )
            val fat = lib.getBodyFat(weightKg, impedanceOhm.toFloat())
            m[MeasurementType.BODY_FAT] = Percent(fat)
            m[MeasurementType.WATER] = Percent(lib.getWater(fat))
            m[MeasurementType.BONE] = Kg(lib.getBoneMass(weightKg, impedanceOhm.toFloat()))
            m[MeasurementType.VISCERAL_FAT] = lib.getVisceralFat(weightKg)
            m[MeasurementType.MUSCLE] = Percent(lib.getMuscle(weightKg, impedanceOhm.toFloat()))
            m[MeasurementType.LBM] =
                Kg(lib.getLBM(weightKg, m[MeasurementType.BODY_FAT]?.value ?: 0f))
        } catch (t: Throwable) {
            logW("T9140: body composition failed, saving weight and impedance: ${t.message}")
        }
        return m
    }

    private fun unitCode(user: ScaleUser): Int = when (user.scaleUnit) {
        WeightUnit.KG -> 0x00
        WeightUnit.LB -> 0x01
        WeightUnit.ST -> 0x02
    }

    /** SEDENTARY/MILD → 0, MODERATE → 1, HEAVY/EXTREME → 2 (matches the legacy mapping). */
    private fun peopleType(level: ActivityLevel): Int = when (level) {
        ActivityLevel.SEDENTARY -> 0
        ActivityLevel.MILD -> 0
        ActivityLevel.MODERATE -> 1
        ActivityLevel.HEAVY -> 2
        ActivityLevel.EXTREME -> 2
    }

    private companion object {
        /** How long a settled weight waits for its body-composition record before being saved bare. */
        const val LIVE_GRACE_MS = 6_000L

        /** Delay before the first history request, so the unit/clock writes go out alone. */
        const val HISTORY_REQUEST_DELAY_MS = 800L

        /** Settle → history request: the BIA run needs a moment after the weight stops moving. */
        const val HISTORY_AFTER_SETTLE_DELAY_MS = 2_500L

        /** Two rows are the same weigh-in when the weights are this close … */
        const val WEIGHT_TOLERANCE_KG = 0.3f

        /** … and the timestamps are within this window (the scale and the phone disagree slightly). */
        const val DUPLICATE_WINDOW_MS = 15 * 60 * 1000L
    }
}
