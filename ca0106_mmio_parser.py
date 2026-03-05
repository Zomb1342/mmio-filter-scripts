#!/usr/bin/env python3
"""
CA0106 MMIO Log Parser
Parses MMIO traces for Creative CA0106 (Sound Blaster Live! 24-bit / Audigy LS)
based on Linux kernel driver register definitions (ca0106.h).

Usage: python ca0106_mmio_parser.py <logfile>
       or pipe log via stdin
"""

import sys
import re

# =============================================================================
# Direct PCI BAR0 Registers
# =============================================================================
DIRECT_REGISTERS = {
    0x00: "CA0106_PTR",
    0x04: "CA0106_DATA",
    0x08: "CA0106_IPR",
    0x0c: "CA0106_INTE",
    0x10: "CA0106_UNKNOWN10",
    0x14: "CA0106_HCFG",
    0x18: "CA0106_GPIO",
    0x1c: "CA0106_AC97DATA",
    0x1e: "CA0106_AC97ADDRESS",
}

# =============================================================================
# Indirect Registers (accessed via PTR + DATA)
# =============================================================================
INDIRECT_REGISTERS = {
    0x00: "PLAYBACK_LIST_ADDR",
    0x01: "PLAYBACK_LIST_SIZE",
    0x02: "PLAYBACK_LIST_PTR",
    0x03: "PLAYBACK_UNKNOWN3",
    0x04: "PLAYBACK_DMA_ADDR",
    0x05: "PLAYBACK_PERIOD_SIZE",
    0x06: "PLAYBACK_POINTER",
    0x07: "PLAYBACK_PERIOD_END_ADDR",
    0x08: "PLAYBACK_FIFO_OFFSET_ADDRESS",
    0x09: "PLAYBACK_UNKNOWN9",
    0x10: "CAPTURE_DMA_ADDR",
    0x11: "CAPTURE_BUFFER_SIZE",
    0x12: "CAPTURE_POINTER",
    0x13: "CAPTURE_FIFO_OFFSET_ADDRESS",
    0x20: "PLAYBACK_LAST_SAMPLE",
    0x40: "BASIC_INTERRUPT",
    0x41: "SPCS0",
    0x42: "SPCS1",
    0x43: "SPCS2",
    0x44: "SPCS3",
    0x45: "SPDIF_SELECT1",
    0x46: "WATERMARK",
    0x49: "SPDIF_INPUT_STATUS",
    0x60: "CAPTURE_SOURCE",
    0x61: "CAPTURE_VOLUME1",
    0x62: "CAPTURE_VOLUME2",
    0x63: "PLAYBACK_ROUTING1",
    0x64: "PLAYBACK_ROUTING2",
    0x65: "PLAYBACK_MUTE",
    0x66: "PLAYBACK_VOLUME1",
    0x67: "CAPTURE_ROUTING1",
    0x68: "CAPTURE_ROUTING2",
    0x69: "CAPTURE_MUTE",
    0x6a: "PLAYBACK_VOLUME2",
    0x6b: "UNKNOWN6b",
    0x6c: "MIDI_UART_A_DATA",
    0x6d: "MIDI_UART_A_CMD",
    0x6e: "MIDI_UART_B_DATA",
    0x6f: "MIDI_UART_B_CMD",
    0x70: "SAMPLE_RATE_TRACKER_STATUS",
    0x71: "CAPTURE_CONTROL",
    0x72: "SPDIF_SELECT2",
    0x73: "UNKNOWN73",
    0x74: "CHIP_VERSION",
    0x75: "EXTENDED_INT_MASK",
    0x76: "EXTENDED_INT",
    0x77: "COUNTER77",
    0x78: "COUNTER78",
    0x79: "EXTENDED_INT_TIMER",
    0x7a: "SPI",
    0x7b: "I2C_A",
    0x7c: "I2C_D0",
    0x7d: "I2C_D1",
}

# Channel name mapping for SPCS registers
SPCS_NAMES = {
    0x41: "Rear",
    0x42: "Front",
    0x43: "Center/LFE",
    0x44: "Unknown/Side",
}

# Channel name mapping for playback
PLAYBACK_CHANNEL_NAMES = {
    0: "Front",
    1: "Center/LFE",
    2: "Unknown",
    3: "Rear",
}


# =============================================================================
# Bitfield Decoders
# =============================================================================

def decode_spcs_channel0(value):
    """Decode SPDIF Channel Status register, channel 0 (main status bits)."""
    fields = []

    clk_acc = (value >> 28) & 0x3
    clk_acc_map = {
        0: "1000 PPM",
        1: "50 PPM",
        2: "Variable",
        3: "Reserved",
    }
    fields.append(f"  Clock Accuracy:     {clk_acc_map.get(clk_acc, f'Unknown ({clk_acc})')}")

    sample_rate = (value >> 24) & 0xf
    sr_map = {
        0x0: "44.1 kHz",
        0x2: "48 kHz",
        0x3: "32 kHz",
    }
    fields.append(f"  Sample Rate:        {sr_map.get(sample_rate, f'Unknown (0x{sample_rate:x})')}")

    chan_num = (value >> 20) & 0xf
    cn_map = {
        0x0: "Unspecified",
        0x1: "Left",
        0x2: "Right",
    }
    fields.append(f"  Channel Number:     {cn_map.get(chan_num, f'0x{chan_num:x}')}")

    src_num = (value >> 16) & 0xf
    fields.append(f"  Source Number:      {'Unspecified' if src_num == 0 else f'0x{src_num:x}'}")

    gen_status = (value >> 15) & 1
    fields.append(f"  Generation Status:  {'Original' if gen_status else 'Copy'}")

    cat_code = (value >> 8) & 0x7f
    fields.append(f"  Category Code:      0x{cat_code:02x}")

    mode = (value >> 6) & 0x3
    fields.append(f"  Mode:               {mode}")

    emphasis = (value >> 3) & 0x7
    emph_map = {0: "None", 1: "50/15 usec 2 channel"}
    fields.append(f"  Emphasis:           {emph_map.get(emphasis, f'0x{emphasis:x}')}")

    copyright_bit = (value >> 2) & 1
    fields.append(f"  Copyright:          {'Asserted' if copyright_bit else 'Not asserted'}")

    not_audio = (value >> 1) & 1
    fields.append(f"  Data Type:          {'Not audio data' if not_audio else 'Digital audio'}")

    professional = value & 1
    fields.append(f"  Format:             {'Professional (AES3-1992)' if professional else 'Consumer (IEC-958)'}")

    return "\n".join(fields)


def decode_spcs_channel1(value):
    """Decode SPDIF Channel Status register, channel 1 (word length + original sample rate)."""
    fields = []

    word_len = value & 0xf
    wl_map = {
        0x08: "16 bit",
        0x06: "17 bit",
        0x04: "18 bit",
        0x02: "19 bit",
        0x0a: "20 bit (A)",
        0x09: "20 bit",
        0x07: "21 bit",
        0x05: "22 bit",
        0x03: "23 bit",
        0x0b: "24 bit",
    }
    fields.append(f"  Word Length:            {wl_map.get(word_len, f'Unknown (0x{word_len:x})')}")

    orig_sr = (value >> 4) & 0xf
    osr_map = {
        0x0: "Not indicated",
        0x1: "16000 Hz",
        0x3: "32000 Hz",
        0x4: "12000 Hz",
        0x5: "11025 Hz",
        0x6: "8000 Hz",
        0x8: "192000 Hz",
        0x9: "24000 Hz",
        0xa: "96000 Hz",
        0xb: "48000 Hz",
        0xc: "176400 Hz",
        0xd: "22050 Hz",
        0xe: "88200 Hz",
        0xf: "44100 Hz",
    }
    fields.append(f"  Original Sample Rate:   {osr_map.get(orig_sr, f'Unknown (0x{orig_sr:x})')}")

    return "\n".join(fields)


def decode_spdif_select1_channel0(value):
    """Decode SPDIF_SELECT1 register, channel 0."""
    fields = []

    wide_fmt = value & 0xf
    fields.append(f"  Wide SPDIF Format:      0x{wide_fmt:x} (per channel: " +
                  ", ".join([f"ch{i}={'24bit' if (wide_fmt >> i) & 1 else '20bit'}"
                             for i in range(4)]) + ")")

    tristate = (value >> 8) & 0xf
    fields.append(f"  Tristate SPDIF Output:  0x{tristate:x} (per channel: " +
                  ", ".join([f"ch{i}={'Tristate' if (tristate >> i) & 1 else 'Active'}"
                             for i in range(4)]) + ")")

    bypass = (value >> 16) & 0xf
    fields.append(f"  SPDIF Bypass Enable:    0x{bypass:x} (per channel: " +
                  ", ".join([f"ch{i}={'Bypass' if (bypass >> i) & 1 else 'Normal'}"
                             for i in range(4)]) + ")")

    return "\n".join(fields)


def decode_spdif_select1_channel1(value):
    """Decode SPDIF_SELECT1 register, channel 1 (user data)."""
    fields = []
    fields.append(f"  SPDIF 0 User Data [7:0]:   0x{value & 0xff:02x}")
    fields.append(f"  SPDIF 1 User Data [15:8]:  0x{(value >> 8) & 0xff:02x}")
    fields.append(f"  SPDIF 2 User Data [23:16]: 0x{(value >> 16) & 0xff:02x}")
    fields.append(f"  SPDIF 3 User Data [31:24]: 0x{(value >> 24) & 0xff:02x}")
    return "\n".join(fields)


def decode_hcfg(value):
    """Decode Hardware Configuration register."""
    flags = []
    flag_defs = [
        (0x10000000, "STAC", "STAC9460 special mode"),
        (0x08000000, "CAPTURE_I2S_BYPASS", "Bypass I2S input async SRC"),
        (0x04000000, "CAPTURE_SPDIF_BYPASS", "Bypass SPDIF input async SRC"),
        (0x02000000, "PLAYBACK_I2S_BYPASS", "I2S IN1 direct"),
        (0x01000000, "FORCE_LOCK", "Force input SRC tracker lock (test)"),
        (0x00001000, "PLAYBACK_DITHER", "Add dither to playback"),
        (0x00000800, "PLAYBACK_S32_LE", "Playback S32_LE format"),
        (0x00000400, "CAPTURE_S32_LE", "Capture S32_LE format"),
        (0x00000200, "8_CHANNEL_PLAY", "8 channel playback"),
        (0x00000100, "8_CHANNEL_CAPTURE", "8 channel capture"),
        (0x00000080, "MONO", "I2S input mono"),
        (0x00000010, "I2S_OUTPUT", "I2S output disabled"),
        (0x00000008, "AC97", "AC97 2.0 mode"),
        (0x00000004, "LOCK_PLAYBACK_CACHE", "Lock playback cache"),
        (0x00000002, "LOCK_CAPTURE_CACHE", "Lock capture cache"),
        (0x00000001, "AUDIOENABLE", "Audio enabled"),
    ]

    atten = (value >> 13) & 0x3
    atten_map = {0: "0 dB", 1: "6 dB", 2: "12 dB", 3: "Mute"}
    flags.append(f"  Playback Attenuation:  {atten_map.get(atten, 'Unknown')}")

    for mask, name, desc in flag_defs:
        state = "SET" if value & mask else "clear"
        flags.append(f"  {name:.<30s} {state} — {desc}")

    return "\n".join(flags)


def decode_gpio(value):
    """Decode GPIO register."""
    fields = []
    gpi = value & 0xff
    gpo = (value >> 8) & 0xff
    gpo_enable = (value >> 16) & 0xff

    fields.append(f"  GPI [7:0] (inputs):     0x{gpi:02x} (0b{gpi:08b})")
    fields.append(f"  GPO [15:8] (outputs):   0x{gpo:02x} (0b{gpo:08b})")
    fields.append(f"  GPO Enable [23:16]:     0x{gpo_enable:02x} (0b{gpo_enable:08b})")

    # SB Live 24-bit specific GPIO decoding
    fields.append(f"  --- SB Live 24-bit GPIO decode ---")
    fields.append(f"  Bit 8  (GPO0): {'Analog (Mic/Line) in' if (gpo >> 0) & 1 else 'SPDIF in/out'}")
    fields.append(f"  Bit 9  (GPO1): {'Analog out enabled' if (gpo >> 1) & 1 else 'Analog out muted'}")
    fields.append(f"  Bit 10 (GPO2): {'Mic-in' if (gpo >> 2) & 1 else 'Line-in'}")
    fields.append(f"  Bit 12 (GPO4): {'96 kHz analog out' if (gpo >> 4) & 1 else '48 kHz analog out'}")
    fields.append(f"  Bit 14 (GPO6): {'Analog out enabled' if (gpo >> 6) & 1 else 'Analog out muted'}")

    return "\n".join(fields)


def decode_ipr(value):
    """Decode Interrupt Pending Register."""
    flags = []
    flag_defs = [
        (0x00020000, "MIDI_RX_B"),
        (0x00010000, "MIDI_TX_B"),
        (0x00004000, "SPDIF_IN_USER"),
        (0x00002000, "SPDIF_OUT_USER"),
        (0x00001000, "SPDIF_OUT_FRAME"),
        (0x00000800, "SPI"),
        (0x00000400, "I2C_EEPROM"),
        (0x00000200, "I2C_DAC"),
        (0x00000100, "AI"),
        (0x00000080, "GPI"),
        (0x00000040, "SRC_LOCKED"),
        (0x00000020, "SPDIF_STATUS"),
        (0x00000010, "TIMER2 (192kHz)"),
        (0x00000008, "TIMER1 (44.1kHz)"),
        (0x00000004, "MIDI_RX_A"),
        (0x00000002, "MIDI_TX_A"),
        (0x00000001, "PCI"),
    ]
    active = []
    for mask, name in flag_defs:
        if value & mask:
            active.append(name)
    if active:
        flags.append(f"  Active: {', '.join(active)}")
    else:
        flags.append(f"  No interrupts pending")
    return "\n".join(flags)


def decode_inte(value):
    """Decode Interrupt Enable Register."""
    flags = []
    flag_defs = [
        (0x00020000, "MIDI_RX_B"),
        (0x00010000, "MIDI_TX_B"),
        (0x00004000, "SPDIF_IN_USER"),
        (0x00002000, "SPDIF_OUT_USER"),
        (0x00001000, "SPDIF_OUT_FRAME"),
        (0x00000800, "SPI"),
        (0x00000400, "I2C_EEPROM"),
        (0x00000200, "I2C_DAC"),
        (0x00000100, "AI"),
        (0x00000080, "GPI"),
        (0x00000040, "SRC_LOCKED"),
        (0x00000020, "SPDIF_STATUS"),
        (0x00000010, "TIMER2 (192kHz)"),
        (0x00000008, "TIMER1 (44.1kHz)"),
        (0x00000004, "MIDI_RX_A"),
        (0x00000002, "MIDI_TX_A"),
        (0x00000001, "PCI"),
    ]
    enabled = []
    for mask, name in flag_defs:
        if value & mask:
            enabled.append(name)
    if enabled:
        flags.append(f"  Enabled: {', '.join(enabled)}")
    else:
        flags.append(f"  No interrupts enabled")
    return "\n".join(flags)


def decode_basic_interrupt(value):
    """Decode BASIC_INTERRUPT register (0x40)."""
    fields = []

    start_play = value & 0xf
    fields.append(f"  Start Playback [3:0]:       0x{start_play:x} (" +
                  ", ".join([f"ch{i}={'ON' if (start_play >> i) & 1 else 'off'}"
                             for i in range(4)]) + ")")

    start_cap = (value >> 8) & 0xf
    fields.append(f"  Start Capture [11:8]:       0x{start_cap:x} (" +
                  ", ".join([f"ch{i}={'ON' if (start_cap >> i) & 1 else 'off'}"
                             for i in range(4)]) + ")")

    rate_map = {0: "48kHz", 1: "44.1kHz", 2: "96kHz", 3: "192kHz"}
    for i in range(4):
        rate = (value >> (16 + i * 2)) & 0x3
        fields.append(f"  Playback Rate ch{i} [{17 + i*2}:{16 + i*2}]:  {rate_map.get(rate, '?')}")

    mix_in = (value >> 24) & 0xf
    fields.append(f"  Mixer In Enable [27:24]:    0x{mix_in:x} (" +
                  ", ".join([f"ch{i}={'ON' if (mix_in >> i) & 1 else 'off'}"
                             for i in range(4)]) + ")")

    mix_out = (value >> 28) & 0xf
    fields.append(f"  Mixer Out Enable [31:28]:   0x{mix_out:x} (" +
                  ", ".join([f"ch{i}={'ON' if (mix_out >> i) & 1 else 'off'}"
                             for i in range(4)]) + ")")

    return "\n".join(fields)


def decode_capture_control_ch0(value):
    """Decode CAPTURE_CONTROL register, channel 0."""
    fields = []

    rate_map = {0: "48kHz", 1: "44.1kHz", 2: "96kHz", 3: "192kHz"}
    rate_map_in = {0: "48kHz", 1: "N/A", 2: "96kHz", 3: "192kHz"}

    samp_out = value & 0x3
    fields.append(f"  Sample Output Rate [1:0]:     {rate_map.get(samp_out, '?')}")

    samp_in = (value >> 2) & 0x3
    fields.append(f"  Sample Input Rate [3:2]:      {rate_map_in.get(samp_in, '?')}")

    src_src = (value >> 4) & 0x1
    fields.append(f"  SRC Input Source [4]:         {'Analog' if src_src else 'Digital mixer'}")

    rec_rate = (value >> 8) & 0x3
    fields.append(f"  Record Rate [9:8]:            {rate_map_in.get(rec_rate, '?')}")

    rec_mix = (value >> 10) & 0x7
    fields.append(f"  Record Mixer Out Enable [12:10]: 0x{rec_mix:x}")

    i2s_in_rate = (value >> 14) & 0x3
    fields.append(f"  I2S Input Rate Master [15:14]:   {rate_map.get(i2s_in_rate, '?')}")

    i2s_out_rate = (value >> 16) & 0x3
    fields.append(f"  I2S Output Rate [17:16]:         {rate_map.get(i2s_out_rate, '?')}")

    i2s_out_src = (value >> 18) & 0x1
    fields.append(f"  I2S Output Source [18]:          {'SRC' if i2s_out_src else 'Host'}")

    rec_mix_i2s = (value >> 19) & 0x3
    fields.append(f"  Record Mixer I2S Enable [20:19]: 0x{rec_mix_i2s:x}")

    i2s_out_mclk = (value >> 21) & 0x1
    fields.append(f"  I2S Out Master Clock [21]:       {'512x' if i2s_out_mclk else '256x'} I2S output rate")

    i2s_in_mclk = (value >> 22) & 0x1
    fields.append(f"  I2S In Master Clock [22]:        {'512x' if i2s_in_mclk else '256x'} I2S input rate")

    i2s_mode = (value >> 23) & 0x1
    fields.append(f"  I2S Input Mode [23]:             {'Master' if i2s_mode else 'Slave'}")

    spdif_out_rate = (value >> 24) & 0x3
    fields.append(f"  SPDIF Output Rate [25:24]:       {rate_map.get(spdif_out_rate, '?')}")

    spdif_out_src = (value >> 26) & 0x1
    fields.append(f"  SPDIF Output Source [26]:        {'SRC' if spdif_out_src else 'Host'}")

    rec_src0_map = {0: "SPDIF in", 1: "I2S in", 2: "AC97 Mic", 3: "AC97 PCM"}
    rec_src0 = (value >> 28) & 0x3
    fields.append(f"  Record Source 0 [29:28]:         {rec_src0_map.get(rec_src0, '?')}")

    rec_src1 = (value >> 30) & 0x3
    fields.append(f"  Record Source 1 [31:30]:         {rec_src0_map.get(rec_src1, '?')}")

    return "\n".join(fields)


def decode_capture_control_ch1(value):
    """Decode CAPTURE_CONTROL register, channel 1 (I2S input volumes)."""
    fields = []
    fields.append(f"  I2S Input 0 Volume Right [7:0]:   0x{value & 0xff:02x}")
    fields.append(f"  I2S Input 0 Volume Left [15:8]:   0x{(value >> 8) & 0xff:02x}")
    fields.append(f"  I2S Input 1 Volume Right [23:16]: 0x{(value >> 16) & 0xff:02x}")
    fields.append(f"  I2S Input 1 Volume Left [31:24]:  0x{(value >> 24) & 0xff:02x}")
    return "\n".join(fields)


def decode_capture_control_ch2(value):
    """Decode CAPTURE_CONTROL register, channel 2 (SPDIF input volume)."""
    fields = []
    fields.append(f"  SPDIF Input Volume Right [23:16]: 0x{(value >> 16) & 0xff:02x}")
    fields.append(f"  SPDIF Input Volume Left [31:24]:  0x{(value >> 24) & 0xff:02x}")
    return "\n".join(fields)


def decode_spdif_select2(value):
    """Decode SPDIF_SELECT2 register (0x72), channel 0."""
    fields = []

    ac97_out = value & 0x3f
    fields.append(f"  AC97 Output Enable [5:0]:   0x{ac97_out:02x}")

    i2s_out = (value >> 16) & 0xf
    fields.append(f"  I2S Output Enable [19:16]:  0x{i2s_out:x}")
    fields.append(f"    Front:      {'Enabled' if i2s_out & 0x1 else 'Disabled'}")
    fields.append(f"    Center/LFE: {'Enabled' if i2s_out & 0x2 else 'Disabled'}")
    fields.append(f"    Rear:       {'Enabled' if i2s_out & 0x8 else 'Disabled'}")

    spdif_out = (value >> 24) & 0xf
    fields.append(f"  SPDIF Output Enable [27:24]: 0x{spdif_out:x}")

    return "\n".join(fields)


def decode_playback_routing1(value):
    """Decode PLAYBACK_ROUTING1 register (0x63)."""
    fields = []
    for i in range(8):
        dest = (value >> (i * 4)) & 0x7
        fields.append(f"  Host channel {i} -> SPDIF Mixer channel {dest}")
    return "\n".join(fields)


def decode_playback_routing2(value):
    """Decode PLAYBACK_ROUTING2 register (0x64)."""
    fields = []
    for i in range(8):
        dest = (value >> (i * 4)) & 0x7
        fields.append(f"  SRC channel {i} -> SPDIF Mixer channel {dest}")
    return "\n".join(fields)


def decode_capture_routing1(value):
    """Decode CAPTURE_ROUTING1 register (0x67)."""
    fields = []
    for i in range(8):
        dest = (value >> (i * 4)) & 0x7
        fields.append(f"  Host channel {i} -> I2S Mixer channel {dest}")
    return "\n".join(fields)


def decode_capture_routing2(value):
    """Decode CAPTURE_ROUTING2 register (0x68)."""
    fields = []
    for i in range(8):
        dest = (value >> (i * 4)) & 0x7
        fields.append(f"  SRC channel {i} -> I2S Mixer channel {dest}")
    return "\n".join(fields)


def decode_playback_mute(value):
    """Decode PLAYBACK_MUTE register (0x65)."""
    fields = []
    inv_src = value & 0xff
    inv_host = (value >> 8) & 0xff
    dis_src = (value >> 16) & 0xff
    dis_host = (value >> 24) & 0xff
    fields.append(f"  Invert SRC to SPDIF Mixer [7:0]:     0x{inv_src:02x}")
    fields.append(f"  Invert Host to SPDIF Mixer [15:8]:   0x{inv_host:02x}")
    fields.append(f"  SRC to SPDIF Mixer Disable [23:16]:  0x{dis_src:02x}")
    fields.append(f"  Host to SPDIF Mixer Disable [31:24]: 0x{dis_host:02x}")
    return "\n".join(fields)


def decode_capture_mute(value):
    """Decode CAPTURE_MUTE register (0x69)."""
    fields = []
    inv_src = value & 0xff
    inv_host = (value >> 8) & 0xff
    dis_src = (value >> 16) & 0xff
    dis_host = (value >> 24) & 0xff
    fields.append(f"  Invert SRC to I2S Mixer [7:0]:     0x{inv_src:02x}")
    fields.append(f"  Invert Host to I2S Mixer [15:8]:   0x{inv_host:02x}")
    fields.append(f"  SRC to I2S Mixer Disable [23:16]:  0x{dis_src:02x}")
    fields.append(f"  Host to I2S Mixer Disable [31:24]: 0x{dis_host:02x}")
    return "\n".join(fields)


def decode_volume(value, mixer_name):
    """Decode a volume register (0x66 or 0x6a). One per stereo stream pair."""
    fields = []
    src_r = value & 0xff
    src_l = (value >> 8) & 0xff
    host_r = (value >> 16) & 0xff
    host_l = (value >> 24) & 0xff

    def vol_str(v):
        if v == 0xff:
            return "Mute"
        elif v == 0x00:
            return "+12 dB"
        elif v == 0x30:
            return "0 dB"
        elif v == 0xfe:
            return "-51.5 dB"
        else:
            return f"0x{v:02x}"

    fields.append(f"  SRC Right Volume [7:0]:    {vol_str(src_r)}")
    fields.append(f"  SRC Left Volume [15:8]:    {vol_str(src_l)}")
    fields.append(f"  Host Right Volume [23:16]: {vol_str(host_r)}")
    fields.append(f"  Host Left Volume [31:24]:  {vol_str(host_l)}")
    return "\n".join(fields)


def decode_capture_source(value):
    """Decode CAPTURE_SOURCE register (0x60)."""
    fields = []

    src_map = {
        0: "SPDIF mixer output",
        1: "I2S mixer output",
        2: "SPDIF input",
        3: "I2S input",
        4: "AC97 capture",
        5: "SRC output",
    }

    rec_map = value & 0xffff
    fields.append(f"  Record Map [15:0]:  0x{rec_map:04x}")
    for i in range(4):
        mapped = (rec_map >> (i * 2)) & 0x3
        fields.append(f"    Record channel {i} mapped to channel {mapped}")

    for i in range(4):
        src = (value >> (16 + i * 4)) & 0xf
        fields.append(f"  Capture Source Channel {i} [{19 + i*4}:{16 + i*4}]: "
                       f"{src_map.get(src, f'Unknown ({src})')}")

    return "\n".join(fields)


def decode_extended_int_mask(value):
    """Decode EXTENDED_INT_MASK register (0x75)."""
    fields = []
    flag_defs = [
        (0x00000001, "Half period playback"),
        (0x00000010, "Full period playback"),
        (0x00000100, "Half buffer playback"),
        (0x00001000, "Full buffer playback"),
        (0x00010000, "Half buffer capture"),
        (0x00100000, "Full buffer capture"),
        (0x01000000, "End audio playback"),
        (0x40000000, "Half buffer xrun"),
        (0x80000000, "Full buffer xrun"),
    ]
    enabled = []
    for mask, name in flag_defs:
        if value & mask:
            enabled.append(name)
    if enabled:
        fields.append(f"  Enabled: {', '.join(enabled)}")
    else:
        fields.append(f"  No extended interrupts enabled")
    return "\n".join(fields)


def decode_sample_rate_tracker(value):
    """Decode SAMPLE_RATE_TRACKER_STATUS register (0x70)."""
    fields = []
    est_rate = value & 0xfffff
    rate_relative = est_rate / 0x8000
    est_hz = rate_relative * 48000
    fields.append(f"  Estimated Rate [19:0]:  0x{est_rate:05x} ({est_hz:.0f} Hz, {rate_relative:.4f} x 48kHz)")
    fields.append(f"  Rate Locked [20]:       {'Yes' if (value >> 20) & 1 else 'No'}")
    fields.append(f"  SPDIF Locked [21]:      {'Yes' if (value >> 21) & 1 else 'No'}")
    fields.append(f"  Valid Audio [22]:       {'Yes' if (value >> 22) & 1 else 'No'}")
    return "\n".join(fields)


def decode_spi(value):
    """Decode SPI register value (WM8768 DAC)."""
    fields = []
    spi_reg = (value >> 9) & 0x7f
    spi_data = value & 0x1ff

    spi_reg_names = {
        0: "LDA1 (Left Digital Atten 1)",
        1: "RDA1 (Right Digital Atten 1)",
        2: "PL/IZD/PDWN",
        3: "FMT/LRP/BCP/IWL/PHASE",
        4: "LDA2 (Left Digital Atten 2)",
        5: "RDA2 (Right Digital Atten 2)",
        6: "LDA3 (Left Digital Atten 3)",
        7: "RDA3 (Right Digital Atten 3)",
        8: "MASTDA (Master Digital Atten)",
        9: "DMUTE0/1/2",
        10: "MS/RATE/DACD0/1/2/PWRDNALL",
        13: "LDA4 (Left Digital Atten 4)",
        14: "RDA4 (Right Digital Atten 4)",
        15: "DMUTE4/PHASE4/DACD4",
    }

    fields.append(f"  SPI Register:  {spi_reg} — {spi_reg_names.get(spi_reg, 'Unknown')}")
    fields.append(f"  SPI Data:      0x{spi_data:03x} (0b{spi_data:09b})")

    # Decode attenuation registers
    if spi_reg in (0, 1, 4, 5, 6, 7, 8, 13, 14):
        update = "Yes" if spi_data & 0x100 else "No"
        atten = spi_data & 0xff
        if atten == 0xff:
            db_str = "0 dB"
        elif atten == 0x00:
            db_str = "-inf dB (Mute)"
        else:
            db_str = f"0x{atten:02x}"
        fields.append(f"    Update bit:    {update}")
        fields.append(f"    Attenuation:   {db_str}")

    # Decode format register
    if spi_reg == 3:
        fmt = spi_data & 0x3
        fmt_map = {0: "Right Justified", 1: "Left Justified", 2: "I2S", 3: "DSP"}
        fields.append(f"    Format:        {fmt_map.get(fmt, '?')}")
        fields.append(f"    LRP (invert LRCLK): {'Yes' if spi_data & 0x4 else 'No'}")
        fields.append(f"    BCP (invert BCLK):  {'Yes' if spi_data & 0x8 else 'No'}")
        iwl = (spi_data >> 4) & 0x3
        iwl_map = {0: "16-bit", 1: "20-bit", 2: "24-bit", 3: "32-bit"}
        fields.append(f"    Word Length:   {iwl_map.get(iwl, '?')}")
        fields.append(f"    Phase 0:       {'Inverted' if spi_data & 0x40 else 'Normal'}")
        fields.append(f"    Phase 1:       {'Inverted' if spi_data & 0x80 else 'Normal'}")
        fields.append(f"    Phase 2:       {'Inverted' if spi_data & 0x100 else 'Normal'}")

    # Decode master/rate register
    if spi_reg == 10:
        fields.append(f"    Master mode:   {'Yes' if spi_data & 0x20 else 'No'}")
        rate = (spi_data >> 6) & 0x7
        rate_map = {0: "128x", 1: "192x", 2: "256x", 3: "384x", 4: "512x", 5: "768x"}
        fields.append(f"    MCLK ratio:    {rate_map.get(rate, '?')}")
        fields.append(f"    DACD0:         {'Power down' if spi_data & 0x2 else 'Active'}")
        fields.append(f"    DACD1:         {'Power down' if spi_data & 0x4 else 'Active'}")
        fields.append(f"    DACD2:         {'Power down' if spi_data & 0x8 else 'Active'}")
        fields.append(f"    PWRDNALL:      {'Power down ALL' if spi_data & 0x10 else 'Normal'}")

    # Decode mute register
    if spi_reg == 9:
        fields.append(f"    DMUTE0:  {'Muted' if spi_data & 0x8 else 'Active'}")
        fields.append(f"    DMUTE1:  {'Muted' if spi_data & 0x10 else 'Active'}")
        fields.append(f"    DMUTE2:  {'Muted' if spi_data & 0x20 else 'Active'}")

    # Decode power down / phase register 2
    if spi_reg == 2:
        fields.append(f"    Power Down All DACs: {'Yes' if spi_data & 0x4 else 'No'}")
        pl_l = (spi_data >> 5) & 0x3
        pl_r = (spi_data >> 7) & 0x3
        ch_map = {0: "Mute", 1: "Left", 2: "Right", 3: "(L+R)/2"}
        fields.append(f"    Left channel source:  {ch_map.get(pl_l, '?')}")
        fields.append(f"    Right channel source: {ch_map.get(pl_r, '?')}")
        fields.append(f"    Infinite Zero Detect: {'Enabled' if not (spi_data & 0x10) else 'Disabled'}")

    if spi_reg == 15:
        fields.append(f"    DACD4:   {'Power down' if spi_data & 0x1 else 'Active'}")
        fields.append(f"    DMUTE4:  {'Muted' if spi_data & 0x4 else 'Active'}")
        fields.append(f"    Phase 4: {'Inverted' if spi_data & 0x8 else 'Normal'}")

    return "\n".join(fields)


def decode_i2c_a(value):
    """Decode I2C Address register (0x7b)."""
    fields = []
    addr = (value >> 1) & 0x7f
    rw = value & 0x1
    fields.append(f"  I2C Address [7:1]:  0x{addr:02x}")
    fields.append(f"  R/W [0]:            {'Read' if rw else 'Write'}")
    fields.append(f"  Start [8]:          {'Yes' if (value >> 8) & 1 else 'No'}")
    fields.append(f"  Abort [9]:          {'Yes' if (value >> 9) & 1 else 'No'}")
    fields.append(f"  Last [10]:          {'Yes' if (value >> 10) & 1 else 'No'}")
    fields.append(f"  Byte Mode [11]:     {'Yes' if (value >> 11) & 1 else 'No'}")
    return "\n".join(fields)


def decode_i2c_d(value):
    """Decode I2C Data register (0x7c / 0x7d)."""
    fields = []
    dat = (value >> 16) & 0x1ff
    reg = (value >> 25) & 0x7f
    fields.append(f"  ADC Register [31:25]:  0x{reg:02x}")
    fields.append(f"  ADC Data [24:16]:      0x{dat:03x}")
    return "\n".join(fields)


def decode_playback_period_end(value):
    """Decode PLAYBACK_PERIOD_END_ADDR register (0x07)."""
    fields = []
    end_addr = value & 0xffff
    stop_flag = (value >> 16) & 1
    fields.append(f"  End Address [15:0]: 0x{end_addr:04x}")
    fields.append(f"  Stop Flag [16]:     {'Stop' if stop_flag else 'Continue'}")
    return "\n".join(fields)


# =============================================================================
# Main Parser Class
# =============================================================================

class CA0106Parser:
    def __init__(self):
        self.current_ptr_reg = None
        self.current_ptr_chan = None
        self.current_ptr_raw = None
        self.line_num = 0

    def get_indirect_reg_name(self, reg):
        """Look up indirect register name, handling ranges like CAPTURE_CACHE_DATA."""
        if reg in INDIRECT_REGISTERS:
            return INDIRECT_REGISTERS[reg]
        if 0x50 <= reg <= 0x5f:
            return f"CAPTURE_CACHE_DATA[0x{reg - 0x50:x}]"
        if 0x0a <= reg <= 0x0f:
            return f"PLAYBACK_UNKNOWN (0x{reg:02x})"
        if 0x14 <= reg <= 0x1f:
            return f"CAPTURE_UNKNOWN (0x{reg:02x})"
        if 0x21 <= reg <= 0x3f:
            return f"UNUSED (0x{reg:02x})"
        return f"UNKNOWN_REG (0x{reg:02x})"

    def decode_indirect_value(self, reg, chan, value, op):
        """Decode an indirect register value based on register and channel."""

        # SPCS0-SPCS3 (0x41-0x44)
        if reg in (0x41, 0x42, 0x43, 0x44):
            spcs_name = SPCS_NAMES.get(reg, "Unknown")
            if chan == 0:
                return f"  [{spcs_name} SPDIF — Channel Status]\n" + decode_spcs_channel0(value)
            elif chan == 1:
                return f"  [{spcs_name} SPDIF — Word Length/Orig SR]\n" + decode_spcs_channel1(value)

        # SPDIF_SELECT1 (0x45)
        if reg == 0x45:
            if chan == 0:
                return decode_spdif_select1_channel0(value)
            elif chan == 1:
                return decode_spdif_select1_channel1(value)

        # BASIC_INTERRUPT (0x40)
        if reg == 0x40:
            return decode_basic_interrupt(value)

        # CAPTURE_CONTROL (0x71)
        if reg == 0x71:
            if chan == 0:
                return decode_capture_control_ch0(value)
            elif chan == 1:
                return decode_capture_control_ch1(value)
            elif chan == 2:
                return decode_capture_control_ch2(value)

        # SPDIF_SELECT2 (0x72)
        if reg == 0x72 and chan == 0:
            return decode_spdif_select2(value)

        # CHIP_VERSION (0x74)
        if reg == 0x74:
            return f"  Chip Version: 0x{value:02x}"

        # PLAYBACK_ROUTING1 (0x63)
        if reg == 0x63:
            return decode_playback_routing1(value)

        # PLAYBACK_ROUTING2 (0x64)
        if reg == 0x64:
            return decode_playback_routing2(value)

        # CAPTURE_ROUTING1 (0x67)
        if reg == 0x67:
            return decode_capture_routing1(value)

        # CAPTURE_ROUTING2 (0x68)
        if reg == 0x68:
            return decode_capture_routing2(value)

        # PLAYBACK_MUTE (0x65)
        if reg == 0x65:
            return decode_playback_mute(value)

        # CAPTURE_MUTE (0x69)
        if reg == 0x69:
            return decode_capture_mute(value)

        # PLAYBACK_VOLUME1 (0x66)
        if reg == 0x66:
            return decode_volume(value, "SPDIF Mixer")

        # PLAYBACK_VOLUME2 (0x6a)
        if reg == 0x6a:
            return decode_volume(value, "I2S Mixer")

        # CAPTURE_SOURCE (0x60)
        if reg == 0x60:
            return decode_capture_source(value)

        # EXTENDED_INT_MASK (0x75) / EXTENDED_INT (0x76)
        if reg in (0x75, 0x76):
            return decode_extended_int_mask(value)

        # SAMPLE_RATE_TRACKER_STATUS (0x70)
        if reg == 0x70:
            return decode_sample_rate_tracker(value)

        # SPI (0x7a)
        if reg == 0x7a:
            return decode_spi(value)

        # I2C_A (0x7b)
        if reg == 0x7b:
            return decode_i2c_a(value)

        # I2C_D0 / I2C_D1 (0x7c / 0x7d)
        if reg in (0x7c, 0x7d):
            return decode_i2c_d(value)

        # PLAYBACK_LIST_ADDR (0x00)
        if reg == 0x00:
            return f"  DMA List Base Address: 0x{value:08x}"

        # PLAYBACK_LIST_SIZE (0x01)
        if reg == 0x01:
            size = (value >> 16) & 0x3f
            return f"  List Size: {size} entries ({size * 8} bytes)"

        # PLAYBACK_DMA_ADDR (0x04)
        if reg == 0x04:
            return f"  DMA Address: 0x{value:08x}"

        # PLAYBACK_PERIOD_SIZE (0x05)
        if reg == 0x05:
            size = (value >> 16) & 0xffff
            return f"  Period Size: {size} samples (0x{size:04x})"

        # PLAYBACK_POINTER (0x06)
        if reg == 0x06:
            ptr = value & 0xffff
            return f"  Pointer: 0x{ptr:04x}"

             # PLAYBACK_PERIOD_END_ADDR (0x07)
        if reg == 0x07:
            return decode_playback_period_end(value)

        # PLAYBACK_FIFO_OFFSET_ADDRESS (0x08)
        if reg == 0x08:
            offset = (value >> 16) & 0x3f
            cache_valid = value & 0x3f
            return (f"  FIFO Offset Address [21:16]: 0x{offset:02x}\n"
                    f"  Cache Size Valid [5:0]:      0x{cache_valid:02x}")

        # PLAYBACK_LIST_PTR (0x02)
        if reg == 0x02:
            ptr = value & 0x3f
            return f"  List Pointer: {ptr}"

        # PLAYBACK_LAST_SAMPLE (0x20)
        if reg == 0x20:
            return f"  Last Sample Value: 0x{value:08x}"

        # CAPTURE_DMA_ADDR (0x10)
        if reg == 0x10:
            return f"  Capture DMA Address: 0x{value:08x}"

        # CAPTURE_BUFFER_SIZE (0x11)
        if reg == 0x11:
            size = (value >> 16) & 0xffff
            return f"  Capture Buffer Size: {size} samples (0x{size:04x})"

        # CAPTURE_POINTER (0x12)
        if reg == 0x12:
            ptr = value & 0xffff
            return f"  Capture Pointer: 0x{ptr:04x}"

        # CAPTURE_FIFO_OFFSET_ADDRESS (0x13)
        if reg == 0x13:
            offset = (value >> 16) & 0x3f
            cache_valid = value & 0x3f
            return (f"  Capture FIFO Offset [21:16]: 0x{offset:02x}\n"
                    f"  Cache Size Valid [5:0]:      0x{cache_valid:02x}")

        # CAPTURE_VOLUME1 (0x61)
        if reg == 0x61:
            fields = []
            for i in range(4):
                vol = (value >> (i * 8)) & 0xff
                fields.append(f"  Capture Volume ch{i}: 0x{vol:02x}")
            return "\n".join(fields)

        # CAPTURE_VOLUME2 (0x62)
        if reg == 0x62:
            fields = []
            for i in range(4):
                vol = (value >> (i * 8)) & 0xff
                fields.append(f"  Capture Volume ch{i + 4}: 0x{vol:02x}")
            return "\n".join(fields)

        # WATERMARK (0x46)
        if reg == 0x46:
            return f"  Watermark Value: 0x{value:08x}"

        # SPDIF_INPUT_STATUS (0x49)
        if reg == 0x49:
            if chan == 0:
                return f"  [SPDIF Input — Channel Status]\n" + decode_spcs_channel0(value)
            elif chan == 1:
                return f"  [SPDIF Input — Word Length/Orig SR]\n" + decode_spcs_channel1(value)
            elif chan == 2:
                user_data = value & 0xffff
                frame_count = (value >> 16) & 0x3f
                return (f"  SPDIF Input User Data [15:0]:  0x{user_data:04x}\n"
                        f"  SPDIF Input Frame Count [21:16]: {frame_count}")

        # COUNTER77 / COUNTER78 (0x77 / 0x78)
        if reg == 0x77:
            return f"  192kHz Counter: {value & 0x3fffff}"
        if reg == 0x78:
            return f"  44.1kHz Counter: {value & 0x3fffff}"

        # EXTENDED_INT_TIMER (0x79)
        if reg == 0x79:
            return f"  Timer Value: 0x{value:08x}"

        # MIDI registers
        if reg == 0x6c:
            return f"  MIDI UART-A Data: 0x{value & 0xff:02x}"
        if reg == 0x6d:
            avail = "Yes" if value & 0x80 else "No"
            ready = "Yes" if value & 0x40 else "No"
            return (f"  MIDI UART-A Input Available:  {avail}\n"
                    f"  MIDI UART-A Output Ready:     {ready}\n"
                    f"  Raw Status: 0x{value & 0xff:02x}")
        if reg == 0x6e:
            return f"  MIDI UART-B Data: 0x{value & 0xff:02x}"
        if reg == 0x6f:
            avail = "Yes" if value & 0x80 else "No"
            ready = "Yes" if value & 0x40 else "No"
            return (f"  MIDI UART-B Input Available:  {avail}\n"
                    f"  MIDI UART-B Output Ready:     {ready}\n"
                    f"  Raw Status: 0x{value & 0xff:02x}")

        # UNKNOWN6b (0x6b)
        if reg == 0x6b:
            return f"  Unknown6b Value: 0x{value:08x} (readonly)"

        # UNKNOWN73 (0x73)
        if reg == 0x73:
            return f"  Unknown73 Value: 0x{value:08x} (readonly)"

        # CAPTURE_CACHE_DATA (0x50-0x5f)
        if 0x50 <= reg <= 0x5f:
            return f"  Cache Data[0x{reg - 0x50:x}]: 0x{value:08x}"

        return None

    def decode_direct_value(self, offset, value, op):
        """Decode a direct BAR0 register value."""

        if offset == 0x08:  # CA0106_IPR
            return decode_ipr(value)

        if offset == 0x0c:  # CA0106_INTE
            return decode_inte(value)

        if offset == 0x14:  # CA0106_HCFG
            return decode_hcfg(value)

        if offset == 0x18:  # CA0106_GPIO
            return decode_gpio(value)

        if offset == 0x1c:  # CA0106_AC97DATA
            return f"  AC97 Data: 0x{value & 0xffff:04x}"

        if offset == 0x1e:  # CA0106_AC97ADDRESS
            return f"  AC97 Address: 0x{value & 0xff:02x}"

        if offset == 0x10:  # CA0106_UNKNOWN10
            return f"  Unknown10 Value: 0x{value:08x}"

        return None

    def parse_ptr_write(self, value):
        """Parse a write to CA0106_PTR register and extract reg + channel."""
        self.current_ptr_raw = value
        self.current_ptr_chan = value & 0x3
        self.current_ptr_reg = (value >> 16) & 0xfff

    def format_ptr_info(self):
        """Format the current PTR selection as a readable string."""
        if self.current_ptr_reg is None:
            return "UNKNOWN (no PTR write seen)"

        reg = self.current_ptr_reg
        chan = self.current_ptr_chan
        reg_name = self.get_indirect_reg_name(reg)

        chan_info = ""
        # Add context-aware channel naming
        if reg in (0x41, 0x42, 0x43, 0x44):
            spcs_name = SPCS_NAMES.get(reg, "")
            chan_info = f" ({spcs_name}, sub-channel {chan})"
        elif reg in range(0x00, 0x09):
            ch_name = PLAYBACK_CHANNEL_NAMES.get(chan, f"ch{chan}")
            chan_info = f" (Playback: {ch_name})"
        elif reg in range(0x10, 0x14):
            ch_name = PLAYBACK_CHANNEL_NAMES.get(chan, f"ch{chan}")
            chan_info = f" (Capture: {ch_name})"
        else:
            chan_info = f" (Channel {chan})"

        return f"{reg_name} [0x{reg:02x}]{chan_info}"

    def parse_line(self, line):
        """Parse a single MMIO log line and return decoded output."""
        line = line.strip()
        if not line or line.startswith("Operation") or line.startswith("----"):
            return None

        # Try to parse the line format: Operation Offset Value Length
        # Support various common formats
        patterns = [
            # "Write    0x0        0x740000   0x4"
            r'(Read|Write)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)',
            # Also try without 0x prefix
            r'(Read|Write)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',
        ]

        match = None
        for pattern in patterns:
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                break

        if not match:
            return f"  [UNPARSEABLE LINE]: {line}"

        op = match.group(1).capitalize()
        offset = int(match.group(2), 16)
        value = int(match.group(3), 16)
        length = int(match.group(4), 16)

        self.line_num += 1
        output_lines = []

        reg_name = DIRECT_REGISTERS.get(offset, f"UNKNOWN_DIRECT (0x{offset:02x})")
        output_lines.append(f"[{self.line_num:4d}] {op:5s} {reg_name} (BAR+0x{offset:02x}) = "
                            f"0x{value:08x} (len={length})")

        # Handle PTR register writes
        if offset == 0x00 and op == "Write":
            self.parse_ptr_write(value)
            ptr_info = self.format_ptr_info()
            output_lines.append(f"       -> Select: {ptr_info}")

        # Handle DATA register reads/writes
        elif offset == 0x04:
            ptr_info = self.format_ptr_info()
            if op == "Write":
                output_lines.append(f"       -> Write to {ptr_info}: 0x{value:08x}")
            else:
                output_lines.append(f"       -> Read from {ptr_info}: 0x{value:08x}")

            # Decode the value
            if self.current_ptr_reg is not None:
                decoded = self.decode_indirect_value(
                    self.current_ptr_reg, self.current_ptr_chan, value, op)
                if decoded:
                    output_lines.append(decoded)

        # Handle direct register reads/writes (not PTR/DATA)
        elif offset not in (0x00, 0x04):
            decoded = self.decode_direct_value(offset, value, op)
            if decoded:
                output_lines.append(decoded)

        return "\n".join(output_lines)


# =============================================================================
# Main Entry Point
# =============================================================================

def parse_mmio_log(input_lines):
    """Parse an entire MMIO log and return decoded output."""
    parser = CA0106Parser()
    output = []

    output.append("=" * 80)
    output.append("CA0106 MMIO Log Decoder")
    output.append("=" * 80)
    output.append("")

    for line in input_lines:
        result = parser.parse_line(line)
        if result is not None:
            output.append(result)
            output.append("")

    output.append("=" * 80)
    output.append(f"Total operations decoded: {parser.line_num}")
    output.append("=" * 80)

    return "\n".join(output)


def main():
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("CA0106 MMIO Log Parser")
            print("Usage: python ca0106_mmio_parser.py <logfile> [outputfile]")
            print("       or pipe log via stdin")
            print("")
            print("Paste MMIO log lines below (Ctrl+D to finish):")
            print("")
        lines = sys.stdin.readlines()

    result = parse_mmio_log(lines)

    # Determine output filename
    if len(sys.argv) > 2:
        out_filename = sys.argv[2]
    elif len(sys.argv) > 1:
        # Derive from input filename
        base = sys.argv[1]
        if '.' in base:
            base = base.rsplit('.', 1)[0]
        out_filename = base + "_decoded.txt"
    else:
        out_filename = "ca0106_mmio_decoded.txt"

    # Write to file
    try:
        with open(out_filename, 'w') as f:
            f.write(result)
        print(f"Decoded output saved to: {out_filename}")
    except IOError as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    # Also print to console
    print(result)

if __name__ == "__main__":
    main()