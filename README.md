# Overview

This is a rust implementation of the Lumenradio CRMX SuperNova protocol.   It is based on reverse engineering of a small number of devices from packet capture.

It is not an official implementation, nor is it supported in any way by LumenRadio (or BPI for that matter).

In other words: use at your own risk.

The focus is on doing RDM monitoring of devices through the LumenRadio system while running in sACN mode.

# Protocol Overview

The protocol operates entirely via UDP Multicast using a couple addresses to differentiate modes.

## 237.1.1.1

CRMX devices advertise on port 37895 and Multicast IP 237.1.1.1 every two seconds it sends the following packet:

    0000   01 00 00 1a f1 02 09 ee 00 02 04 02 10 01 00 19   ................
    0010   00 00 00 00 6c 6c 65 72 00 00 02 01 64 00 00 00   ....ller....d...
    0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0040   00 00 00 00 00 00 00 74 20 43 6f 6e 74 72 6f 6c   .......t Control
    0050   6c 65 72 00 00 00 00 00 00 00 00 00 00 00 00 00   ler.............
    0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0080   00 00 02 54 58 00 00 00 00 00 00 00 00 00 00 00   ...TX...........
    0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00a0   00 00 0a 65 34 65 00 00 ff ff 00 ff 01 00 00 00   ...e4e..........
    00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00e0   00 00 00 00 00 00 00 00 00 00 00 00 00            .............

- Octets 0x47 through 0x52 contain the text "tController"
- Octets 0x83 and 8x84 contain "TX"
- Octets 0xa2 through 0xa8 appear to be the IP address, followed by the netmask (?)

Supernova transmitted the following packet to the TX CRMX:

    0000   68 00 00 1a f1 02 09 ee ef be ad de

To which it responded with:

    0000   01 00 5e 01 01 01 00 1a f1 02 09 ee 08 00 45 00   ..^...........E.
    0010   00 3e 55 6d 00 00 ff 11 39 75 0a 65 34 65 ed 01   .>Um....9u.e4e..
    0020   01 01 94 07 94 07 00 2a 71 85 69 00 00 1a f1 02   .......*q.i.....
    0030   09 ee 55 4c 02 00 01 00 00 00 00 4c 42 55 46 41   ..UL.......LBUFA
    0040   31 31 30 30 31 31 30 37 31 00 00 35 ff            110011071..5.

I believe the string `1a f1 02 09 ee` is the unique identifier for this device, I do not know the significance of the response.

## 237.200.1.1

Most of the RDM functionality is communicated on 237.200.1.1 ports 60000 and 60001.   Communication on this mulitcast address started immediately after the above response came back.

Primiarily, both sides transmit from port 60000 to port 60001.   For the most part SuperNova sends concise packets, while the remote side responds with 534-bytes of data.   I believe that the remote is responding with a 512-byte buffer with 22 bytes of header.   The 512-byte buffer often contains "junk" and needs to be parsed carefully.

I'm going to call the sides of the comms SN for SuperNova and TX for the CRMX TX.

SN sends:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 00 01 04 00 00                                 *.....

This is precisely 22 bytes long (our suspected header length) and contains our `1a f1 02 09 ee` string after a 0x4242 "BB" header.

TX sends:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 00 01 04 00 00 6e 00 ff 00 00 00 00 4c 00 00   *.....n......L..
    0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0030   00 00 00 00 00 00 ff ff ff ff ff ff ff ff ff ff   ................
    0040   ff ff ff 00 00 00 00 00 00 00 ff ff ff ff ff ff   ................
    0050   ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00d0   00 00 00 00 00 00 00 00 f4 21 00 40 58 22 00 40   .........!.@X".@
    00e0   ac 25 00 40 08 27 00 40 8c 28 00 40 9c 29 00 40   .%.@.'.@.(.@.).@
    00f0   e0 29 00 40 34 2b 00 40 f4 36 00 40 01 00 00 00   .).@4+.@.6.@....
    0100   00 00 00 00 58 3a 00 40 10 00 00 00 b8 f8 70 5a   ....X:.@......pZ
    0110   81 29 78 00 00 00 00 00 00 00 00 00 00 00 00 00   .)x.............
    0120   6c 3a 00 40 00 00 00 00 58 3a 00 40 00 00 00 00   l:.@....X:.@....
    0130   10 00 00 00 44 3a 00 40 00 00 00 00 e8 22 00 40   ....D:.@.....".@
    0140   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0150   00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00   ................
    0160   00 00 00 00 00 00 00 00 b3 01 01 00 00 00 0a 65   ...............e
    0170   64 79 00 00 00 00 00 00 a0 22 00 40 c4 22 00 40   dy.......".@.".@
    0180   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0190   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01f0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0200   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0210   00 00 00 00 00 00                                 ......

If we extract only the 22-byte header, we have this:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 00 01 04 00 00

We again have our `BB` start code, along with 7 NULLs and then our `1a f1 02 09 ee` string.  That string is 5 bytes long, so I suspect we have the following format for the first 14 bytes:

    <BB Hdr> <6 bytes DST> <6 bytes SRC>

So our UID is actually `00 1a f1 02 09 ee` as it's 6 bytes long.  `00 00 00 00 00 00` may be an all call or it may be the SuperNova ID.  

In both of these packets we have 0x00 0x00 as the next two bytes, so they're either pad or unknown.

Starting at 0x10 we have:

SN:
    0010   2a 00 01 04 00 00                                 *.....
TN:
    0010   2a 00 01 04 00 00                                 *.....

So we have some sort of "command code" in these 6 bytes, but no directionality, so for the moment we can ignore whether it's coming from SN or TN.

Here's the next few packets:

    0010   2a 01 01 07 01 00 02                              *......
    0010   2a 02 01 00 03 00 01 47 0d                        *......G.
    0010   2a 03 01 06 01 00 00                              *......
    0010   2a 04 01 06 01 00 04                              *......
    0010   2a 05 01 00 03 00 01 47 04                        *......G.
    0010   2a 06 01 06 01 00 06                              *......

`0x2a` is a `*` character, so I think they're using it as a field delimiter to the command sequence.

The next field is a transaction ID -- it increments with each message so you can match the responses.

I have no idea what any of these messages mean or what the fields mean.

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 2d 01 00 0f 00 01 44 00 00 00 00 00 00 80 fe   *-.....D........
    0020   ff ff ff ff ff                                    .....

This is the last one sent before RDM data starts-- it looks like it may be stepping through some discovery process-- maybe discovering remote CRMX devices?

## RDM

The first RDM-looking packet sent from SN is this one:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 2e 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *.../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 2e 01   .$......LU......
    0030   00 00 00 10 00 01 0c 00 00 00 00 00 00 ff ff ff   ................
    0040   ff ff fe 0f 4e                                    ....N

Deconstructing it a bit, we have our 23 byte header:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 2e 01 00 2f 00 03

DST: `00 1a f1 02 09 ee`, SRC: `00 00 00 00 00 00`

0x2a is the *, 0x2e is our sequence number. The next 0x01 is always there (maybe a protocol ID?), then we have `0x00 0x2f 0x00 0x03` which I'm going to guess means "send an RDM packet!"

The next chunk is this:

   0010   2a 2e 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *.../..D.|...UL.

   `44 07 7c f2 0b 00 55 4c` is unknown, but `0xcc` is the RDM start code.

   So we have an RDM packet:

    0010                                                cc   *.../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 2e 01   .$......LU......
    0030   00 00 00 10 00 01 0c 00 00 00 00 00 00 ff ff ff   ................
    0040   ff ff fe 0f 4e                                    ....N

`4c55` is LumenRadio's ESTA manufacturer ID, in little endian it's `554c` so we see a repeat of some bytes from above in reverse order... `4c55:000bf280` shows up in the header before as `7cf20b0:0554c` 0x7c and 0x80 are pretty fricking close to each other.   But I don't know the significance here.   0x744 in decimal form is 1860 which is maybe a BREAK specification?   Total guess there.

OK, so this RDM packet is an all-call discovery packet.   It asks for EVERY RDM UID to see if anyone is out there.   What's interesting, however, is that it actually seems to have flipped the endianness by bit of the high UID.   Maximum UID should be 0x7FFF_FFFF_FFFF (which is 0b0111...1) this is 0b111...10.   But that's a bit moot.

Anyway, we get this response:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 2e 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *.....d..et.i...
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 2e 01   .$......LU......
    0030   00 00 00 10 00 01 0c 00 00 00 00 00 00 ff ff ff   ................
    0040   ff ff fe 0f 4e 5d 4d 70 07 0e 00 00 5d 46 ff ff   ....N]Mp....]F..
    0050   ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00d0   00 00 00 00 e4 35 00 40 24 38 00 40 52 04 f0 00   .....5.@$8.@R...
    00e0   03 00 00 00 66 37 01 00 5e 7f ff fa e8 9f 80 83   ....f7..^.......
    00f0   4e 2c 08 00 45 00 04 52 c1 54 00 00 01 11 95 6e   N,..E..R.T.....n
    0100   0a 65 64 79 ef ff ff fa e2 ed 0e 76 04 3e 03 d7   .edy.......v.>..
    0110   3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31   <?xml version="1
    0120   2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 75 74   .0" encoding="ut
    0130   66 2d 38 22 3f 3e 3c 73 6f 61 70 3a 45 6e 76 65   f-8"?><soap:Enve
    0140   6c 6f 70 65 20 78 6d 6c 6e 73 3a 73 6f 61 70 3d   lope xmlns:soap=
    0150   22 68 74 74 70 3a 2f 2f 77 77 77 2e 77 33 2e 6f   "http://www.w3.o
    0160   72 67 2f 32 30 30 33 2f 30 35 2f 73 6f 61 70 2d   rg/2003/05/soap-
    0170   65 6e 76 65 6c 6f 70 65 22 20 78 6d 6c 6e 73 3a   envelope" xmlns:
    0180   77 73 61 3d 22 68 74 74 70 3a 2f 2f 73 63 68 65   wsa="http://sche
    0190   6d 61 73 2e 78 6d 6c 73 6f 61 70 2e 6f 72 67 2f   mas.xmlsoap.org/
    01a0   77 73 2f 32 30 30 34 2f 30 38 2f 61 64 64 72 65   ws/2004/08/addre
    01b0   73 73 69 6e 67 22 20 78 6d 6c 6e 73 3a 77 73 64   ssing" xmlns:wsd
    01c0   3d 22 68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73   ="http://schemas
    01d0   2e 78 6d 6c 73 6f 61 70 2e 6f 72 67 2f 77 73 2f   .xmlsoap.org/ws/
    01e0   32 30 30 35 34 3b 00 40 24 39 00 40 aa 01 00 01   20054;.@$9.@....
    01f0   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0200   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0210   00 00 00 00 00 00                                 ......

Which, yeah, is kind of a bunch of data.

But let's look at the first few lines:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 2e 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *.....d..et.i...
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 2e 01   .$......LU......

OK, we have our typical stuff, line 0x10 in particular has this:

    0010   2a 2e 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *.....d..et.i...
            * TN VN .. .. .. [ start of 512 byte buffer  ]

Lne 0x20 looks a lot like the data we were sending, so probably bytes that didn't get overwritten.

Let's look at the next step:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 2f 01 00 09 00 01 4e 7c f2 0b 00 55 4c 00      */.....N|...UL.

    0010   2a 2e 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *.../..D.|...UL.

I interposed the previous "RDM" TX packet below, many of the same bytes but in a different order and missing a byte.  I'm not sure what this one is doing.

So then we get a discovery packet:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 30 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *0../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 2f 01   .$......LU..../.
    0030   00 00 00 10 00 01 0c 00 00 00 00 00 00 7f ff ff   ................
    0040   ff ff ff 0e d0                                    .....

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 51 01 00 2f 00 03 44 07 7b f2 0b 00 55 4c cc   *Q../..D.{...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 51 01   .$......LU....Q.
    0030   00 00 00 10 00 01 0c 40 00 00 00 00 00 7f ff ff   .......@........
    0040   ff ff ff 0f 32                                    ....2

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 5b 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *[../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 5b 01   .$......LU....[.
    0030   00 00 00 10 00 01 0c 36 38 27 10 6d 40 36 38 27   .......68'.m@68'
    0040   10 6d 7f 0c 65                                    .m..e

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 5b 01 01 0a 00 64 07 ff 36 38 27 10 6d 51 07   *[....d..68'.mQ.


This one actually starts with 0x7fff address as it should.  

We get this response (534 bytes, truncated here):

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 30 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *0....d..et.i...
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 2f 01   .$......LU..../.

Line 0x20 matches line 0x20 above, so that's just unmodified buffer.   Comparing this with the last response we get this:

    0010   2a 30 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *0....d..et.i...
    0010   2a 2e 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *.....d..et.i...

So I suspect that this response means "some data was received?"   Total guess, but the next SN packet is this:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 31 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *1../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 31 01   .$......LU....1.
    0030   00 00 00 10 00 01 0c 00 00 00 00 00 00 3f ff ff   .............?..
    0040   ff ff ff 0e 92                                    .....

Which is the left branch in the discovery tree, so it clearly knows data was found.

SN:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 32 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *2../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 32 01   .$......LU....2.
    0030   00 00 00 10 00 01 0c 00 00 00 00 00 00 1f ff ff   ................
    0040   ff ff ff 0e 73                                    ....s

TX:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 32 01 01 0a 00 64 07 00 04 02 00 4c 00 ff ff   *2....d.....L...
    0010   2a 30 01 01 0a 00 64 07 01 65 74 1b 69 d0 fd 09   *0....d..et.i... (from other response)

So now we get something diferent.  And we react accordingly.   My current guess is that octet 0x18 is 00 when nothing is found and 01 when something is found.

SN sends the branch 2 more times and gets a 00 response each time.   Then it moves on.

Further down the discovery tree, we have this sequence:

SN: 

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 98 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *.../..D.|...UL.
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 98 01   .$......LU......
    0030   00 00 00 10 00 01 0c 36 38 0b 10 13 00 36 38 0b   .......68....68.
    0040   10 13 0f 0b 06                                    .....

TN:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 98 01 01 0a 00 64 07 ff 36 38 0b 10 13 0f 06   *.....d..68.....
    0020   01 24 ff ff ff ff ff ff 4c 55 00 0b f2 80 98 01   .$......LU......

In this case, 0x07 is followed by 0xff instead of 0x00 (no data) or 0x01 (some data), and an RDM UID: 3638:0b10130f

SN then sends:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 99 01 00 0a 00 01 4e 7b f2 0b 00 55 4c 07 01   *......N{...UL..

TN:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 99 01 01 07 00 6e 07 52 61 64 69 6f 4c 07 01   *.....n.RadioL..
    0020   dd 4b 14 b1 eb 01 70 17 02 52 e7 00 06 e0 70 00   .K....p..R....p.
    0030   00 52 eb 00 00 52 eb 00 01 00 01 00 00 36 38 0b   .R...R.......68.
    0040   10 13 0f 0b 06 00 00 00 00 00 ff ff ff ff ff ff   ................
    0050   ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

What does this message mean?

Anyway, SN sends:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 9a 01 00 22 00 03 52 7c f2 0b 00 55 4c cc 01   *..."..R|...UL..
    0020   18 36 38 0b 10 13 0f 4c 55 00 0b f2 80 9a 01 00   .68....LU.......
    0030   00 00 10 00 02 00 04 5b                           .......[

Which contains the RDM packet to 3638:0b10130f PID 0x0002 which is DISC_MUTE.   

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 9a 01 01 1d 00 72 cc 01 1a 4c 55 00 0b f2 80   *.....r...LU....
    0020   36 38 0b 10 13 0f 9a 00 00 00 00 11 00 02 02 00   68..............
    0030   00 04 5f 00 02 00 04 5b 01 00 01 00 00 36 38 0b   .._....[.....68.
    0040   10 13 0f 0b 06 00 00 00 00 00 ff ff ff ff ff ff   ................

We get this back, which contains an RDM ACK.  

So we then continue the discovery process.

After discovery is finished, regular RDM looks like this:

SN:

    0000   42 42 00 1a f1 02 09 ee 00 00 00 00 00 00 00 00   BB..............
    0010   2a 26 01 00 22 00 03 52 7c f2 0b 00 55 4c cc 01   *&.."..R|...UL..
    0020   18 36 38 0b 10 13 18 4c 55 00 0b f2 80 26 01 00   .68....LU....&..
    0030   00 00 20 00 80 00 04 7e                           .. ....~

This is a request for PID 0x0080 which is DEVICE_MODEL_DESCRIPTION, we get back this:

TX:

    0000   42 42 00 00 00 00 00 00 00 1a f1 02 09 ee 00 00   BB..............
    0010   2a 26 01 01 3b 00 72 cc 01 38 4c 55 00 0b f2 80   *&..;.r..8LU....
    0020   36 38 0b 10 13 18 26 00 00 00 00 21 00 80 20 4c   68....&....!.. L
    0030   42 58 2d 34 30 4b 2d 4e 46 2d 52 32 20 20 20 20   BX-40K-NF-R2    
    0040   20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 0a                  .
    0050   52 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00   R...............
    0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

Which indicates 0x20 or 32 bytes of data, followed by "LBX-40K-NF-R2" a bunch of spaces and an 0x0a which is a linefeed.

If we compare the SN transmission here of line 0x10 with discovery mode:

    0010   2a 26 01 00 22 00 03 52 7c f2 0b 00 55 4c cc 01   *&.."..R|...UL..
    0010   2a 30 01 00 2f 00 03 44 07 7c f2 0b 00 55 4c cc   *0../..D.|...UL.

We find we're a byte short before we start.   So I'm ont sure how to differentitate these two envelopes.

The previous packet is this:

    0010   2a 25 01 00 22 00 03 52 7c f2 0b 00 55 4c cc 01   *%.."..R|...UL..

So perhaps it's the 0x22 field vs. the 0x24 field?  Looks like the 0x07 is "extra"

