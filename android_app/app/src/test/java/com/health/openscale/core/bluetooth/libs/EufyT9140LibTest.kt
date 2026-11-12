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
 */
package com.health.openscale.core.bluetooth.libs

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Tests for [EufyT9140Lib].
 *
 * The expected command bytes are the ones documented by particleflux's 2021 notes and used by
 * bdr99/eufylife-ble-client, so a passing suite means this port frames commands the way two
 * independent implementations do. The weigh-in frames are the shape the scale sends; the
 * 72.3 kg / 568 Ω sample is the scale's own history record, where the same weight and
 * impedance fields are known-good.
 */
class EufyT9140LibTest {

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // ── commands ────────────────────────────────────────────────────────────────

    @Test
    fun `unit command matches the documented bytes`() {
        assertThat(EufyT9140Lib.toHex(EufyT9140Lib.unitCommand(0)))
            .isEqualTo("ac 02 fe 06 00 00 cc d0")
        assertThat(EufyT9140Lib.toHex(EufyT9140Lib.unitCommand(1)))
            .isEqualTo("ac 02 fe 06 01 00 cc d1")
    }

    @Test
    fun `history request matches the documented bytes`() {
        assertThat(EufyT9140Lib.toHex(EufyT9140Lib.historyRequestCommand()))
            .isEqualTo("ac 02 ff 00 00 00 cf ce")
    }

    @Test
    fun `time sync carries the epoch little endian`() {
        // 1622286379 = Sat 29 May 2021 12:26:19 UTC, the sample from the reverse engineering notes.
        assertThat(EufyT9140Lib.toHex(EufyT9140Lib.timeSyncCommand(1622286379L)))
            .isEqualTo("ac 02 f2 2b 20 b2 60 cc 1b")
    }

    @Test
    fun `checksum wraps to one byte`() {
        assertThat(EufyT9140Lib.checksum(hex("ff 02"))).isEqualTo(0x01)
        assertThat(EufyT9140Lib.checksum(hex("00 00 00"))).isEqualTo(0x00)
    }

    // ── parsing ─────────────────────────────────────────────────────────────────

    @Test
    fun `settled frame decodes weight and impedance`() {
        val reading = EufyT9140Lib.parseReading(hex("ac 02 02 d3 02 38 ca"))

        assertThat(reading).isNotNull()
        assertThat(reading!!.weightKg).isWithin(0.001f).of(72.3f) // 0x02d3 = 723 → 72.3 kg
        assertThat(reading.impedanceOhm).isEqualTo(568)           // 0x0238 = 568 Ω
        assertThat(reading.isFinal).isTrue()
    }

    @Test
    fun `interim frame is flagged as not settled`() {
        val reading = EufyT9140Lib.parseReading(hex("ac 02 02 d3 02 38 ce"))

        assertThat(reading).isNotNull()
        assertThat(reading!!.weightKg).isWithin(0.001f).of(72.3f)
        assertThat(reading.isFinal).isFalse()
    }

    @Test
    fun `missing impedance decodes as weight only`() {
        val reading = EufyT9140Lib.parseReading(hex("ac 02 02 d3 00 00 ca"))

        assertThat(reading).isNotNull()
        assertThat(reading!!.impedanceOhm).isEqualTo(0)
        assertThat(reading.isFinal).isTrue()
    }

    @Test
    fun `command acknowledgements are not read as weigh-ins`() {
        // FE 07 00 00 CC is the scale's time-sync response — byte 6 is not a reading marker.
        assertThat(EufyT9140Lib.parseReading(hex("ac 02 fe 07 00 00 cc d1"))).isNull()
    }

    @Test
    fun `frames that are too short or implausible are rejected`() {
        assertThat(EufyT9140Lib.parseReading(hex("ca"))).isNull()
        assertThat(EufyT9140Lib.parseReading(hex("ac 02 00 00 00 00 ca"))).isNull()   // 0.0 kg
        assertThat(EufyT9140Lib.parseReading(hex("ac 02 00 01 02 38 ca"))).isNull()   // 0.1 kg
    }

    // ── history records ─────────────────────────────────────────────────────────

    @Test
    fun `history start marker is recognised`() {
        assertThat(EufyT9140Lib.isHistoryStart(hex("ac 02 fe 01 00 00 cf ce"))).isTrue()
        // A settled weigh-in frame is not a history marker, despite sharing the prefix.
        assertThat(EufyT9140Lib.isHistoryStart(hex("ac 02 02 d3 02 38 ca"))).isFalse()
        assertThat(EufyT9140Lib.isHistoryStart(hex("ac 02"))).isFalse()
    }

    @Test
    fun `history record decodes the scale's own sample`() {
        // ac02 ff 1c2db260 02d3 0238 0000000000000000 — the record from particleflux's 2021 notes.
        val records = EufyT9140Lib.parseHistoryRecords(hex("ac02ff1c2db26002d302380000000000000000"))

        assertThat(records).hasSize(1)
        val record = records[0]
        // Timestamp is little endian: 0x60b22d1c = Sat 29 May 2021 12:01:32 UTC.
        assertThat(record.epochSeconds).isEqualTo(1622289692L)
        assertThat(record.weightKg).isWithin(0.001f).of(72.3f)
        assertThat(record.impedanceOhm).isEqualTo(568)
    }

    @Test
    fun `history record with two entries yields both`() {
        // 19-byte form: entry at offset 3, spare space at offset 11 holding a second entry.
        val frame = hex("ac02ff1c2db26002d30238" + "1d2db26002d4024a")

        val records = EufyT9140Lib.parseHistoryRecords(frame)

        assertThat(records).hasSize(2)
        assertThat(records[0].weightKg).isWithin(0.001f).of(72.3f)
        assertThat(records[1].epochSeconds).isEqualTo(1622289693L)
        assertThat(records[1].weightKg).isWithin(0.001f).of(72.4f)
        assertThat(records[1].impedanceOhm).isEqualTo(586)
    }

    @Test
    fun `zero filled history space is not a record`() {
        assertThat(EufyT9140Lib.parseHistoryRecords(hex("ac02ff0000000000000000"))).isEmpty()
        assertThat(EufyT9140Lib.parseHistoryRecords(hex("ac 02 ff 00"))).isEmpty()
    }

    @Test
    fun `a weigh-in without a BIA result keeps the weight`() {
        val records = EufyT9140Lib.parseHistoryRecords(hex("ac02ff1c2db26002d3000000000000000000"))

        assertThat(records).hasSize(1)
        assertThat(records[0].weightKg).isWithin(0.001f).of(72.3f)
        assertThat(records[0].impedanceOhm).isEqualTo(0)
    }

    @Test
    fun `a history record is not mistaken for a live frame`() {
        val record = hex("ac02ff1c2db26002d302380000000000000000")

        assertThat(EufyT9140Lib.parseReading(record)).isNull()
        assertThat(EufyT9140Lib.splitFrames(record)).hasSize(1)
    }

    // ── container splitting ─────────────────────────────────────────────────────

    @Test
    fun `a plain notification is one frame`() {
        val frames = EufyT9140Lib.splitFrames(hex("ac 02 02 d3 02 38 ca"))

        assertThat(frames).hasSize(1)
        assertThat(frames[0]).hasLength(7)
    }

    @Test
    fun `a sixteen byte container yields both frames`() {
        // Second frame in the tail, first frame in the head — matches the Python client.
        val container = hex("ac 02 02 d3 02 38 ca 00" + "ac 02 02 d4 02 38 ce 00")

        val frames = EufyT9140Lib.splitFrames(container)
        assertThat(frames).hasSize(2)

        val readings = frames.mapNotNull { EufyT9140Lib.parseReading(it) }
        assertThat(readings).hasSize(2)
        assertThat(readings[0].weightKg).isWithin(0.001f).of(72.4f)
        assertThat(readings[0].isFinal).isFalse()
        assertThat(readings[1].weightKg).isWithin(0.001f).of(72.3f)
        assertThat(readings[1].isFinal).isTrue()
    }

    @Test
    fun `a seventeen byte container yields both frames`() {
        val container = hex("ac 02 02 d3 02 38 ca 00 00" + "ac 02 02 d5 02 38 ce 00")

        val frames = EufyT9140Lib.splitFrames(container)
        assertThat(frames).hasSize(2)
        assertThat(frames.mapNotNull { EufyT9140Lib.parseReading(it) }).hasSize(2)
    }
}
