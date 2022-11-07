# General overview of Reduced Neighbor Report (201)

Also referred to as RNR for short.

Fields:

2 bytes
TBTT Information Field
TBTT Filtered Neighbor AP
TBTT Information Length

1 byte
Operating Class

1 byte
Channel number

TBTT (potential for multiple):

	1 byte
	Neighbor AP TBTT Offset

	6 bytes
	BSSID

	4 bytes
	Short SSID

	1 byte
	BSS Parameters

	1 byte
	PSD subfield

## Wireshark Export

```ascii
Tag: Reduced Neighbor Report
    Tag Number: Reduced Neighbor Report (201)
    Tag length: 17
    Neighbor AP Information
        .... .... .... ..00 = TBTT Information Field: 0
        .... .... .... .0.. = TBTT Filtered Neighbor AP: 0
        .... .... 0000 .... = TBTT Information Count: 0
        0000 1101 .... .... = TBTT Information Length: Neighbor AP TBTT Offset subfield, the BSSID subfield, the Short SSID subfield, the BSS Parameters subfield and the 20 MHz PSD subfield (13)
        Operating Class: 134
        Channel Number: 5
        TBTT Information
            Neighbor AP TBTT Offset: 100
            BSSID: 348a12f84160
            Short SSID: 0x67a8761c
            BSS Parameters: 0x4c
                .... ...0 = OCT Recommended: False
                .... ..0. = Same SSID: False
                .... .1.. = Multiple BSSID: True
                .... 1... = Transmitted BSSID: True
                ...0 .... = Member of ESS with 2.4/5 GHz Co-Located AP: False
                ..0. .... = Unsolicited Probe Responses: False
                .1.. .... = Co-Located AP: True
                0... .... = Reserved: 0x0
            PSD Subfield: -1.0 dBm/MHz

0000   c9 11 00 0d 86 05 64 34 8a 12 f8 41 60 1c 76 a8   ......d4...A`.v.
0010   67 4c fe                                          gL.
```