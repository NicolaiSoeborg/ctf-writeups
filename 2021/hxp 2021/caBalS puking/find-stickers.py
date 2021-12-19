import io, os, struct

MAC_SIZE = 10
INT_SIZE = 4

# Sticker sizes extracted from a stock Signal backup
# Note a few of the stickers are duplicates so their file sizes are equal
sticker_lookup = {96712: [1, 2], 23378: [52, 56], 23082: [25, 27], 180536: [26], 147118: [16], 143805: [13], 131048: [22], 121193: [10], 120549: [9], 117689: [21], 117357: [3], 109893: [23], 103871: [17], 102865: [6], 92830: [11], 92769: [4], 90734: [24], 83778: [5], 76324: [8], 76151: [14], 69978: [78], 66598: [7], 61454: [15], 60146: [12], 58920: [53], 57818: [18], 51775: [19], 49728: [20], 38404: [68], 36200: [69], 30586: [66], 30418: [72], 29460: [58], 28468: [74], 27680: [64], 27370: [60], 26982: [63], 26746: [76], 26264: [45], 25740: [28], 25578: [34], 25216: [61], 25076: [70], 25070: [31], 24188: [36], 23670: [59], 23558: [35], 23300: [75], 22650: [46], 21834: [77], 21694: [71], 21444: [54], 21434: [32], 21280: [41], 21244: [38], 21010: [29], 19978: [65], 19958: [51], 19928: [42], 19748: [44], 19062: [39], 17910: [30], 17832: [43], 17508: [37], 17226: [57], 16996: [50], 16704: [33], 16456: [73], 15618: [49], 15220: [62], 14414: [40], 14362: [55], 14214: [48], 14162: [67], 13596: [47]}
# => Maps sticker file sizes to the sticker id (so we later can XOR the raw sticker bytes with that found offset)

def read_chunk(f):
    # If we find something that points to here, we have found the start of the chunk
    target = f.tell()

    if target == 0:
        print("File fully parsed!")
        exit(0)

    # Seek enough to skip [len][mac]
    f.seek(-(MAC_SIZE + INT_SIZE), os.SEEK_CUR)

    # Speed hack: only look for small chunks as the empty database has no big chunks
    for _ in range(0x00_00_FF_FF):
        chunk_size = struct.unpack(">I", f.read(INT_SIZE))[0]
        if chunk_size < MAC_SIZE or f.tell() + chunk_size != target:
            # Seek the 4 bytes just read
            f.seek(-INT_SIZE, os.SEEK_CUR)

            if f.tell() == 0:
                #print("Not seeking out of file")
                break

            # Move backwards and retry (continue)
            f.seek(-1, os.SEEK_CUR)
            continue

        # We found a good looking offset! :D
        # Skip MAC
        chunk = f.read(chunk_size - MAC_SIZE)

        # Seek till start of chunk
        f.seek(-(chunk_size - MAC_SIZE + INT_SIZE), os.SEEK_CUR)
        return chunk

    # no chunk found, abort!
    f.seek(target)


def find_sticker(f):
    restore_point = f.tell()
    for sticker_len in list(sticker_lookup.keys()):
        if sticker_len > f.tell():
            # print(f"Skipping too big sticker: {sticker_len} > {f.tell()}")
            continue
        f.seek(-sticker_len, os.SEEK_CUR)
        if (chunk := read_chunk(f)):
            sticker_id = sticker_lookup[sticker_len]
            if len(sticker_id) == 2:
                # Change a double sticker into a single sticker on first match:
                sticker_id = ', '.join([str(c) for c in sticker_id])
                sticker_lookup[sticker_len] = [sticker_id]
            else:
                assert len(sticker_id) == 1, sticker_id
                sticker_id = sticker_id[0]
                del sticker_lookup[sticker_len]
            return sticker_len, sticker_id, chunk
        f.seek(restore_point)


if __name__ == '__main__':
    f = io.BytesIO(open('signal-2021-11-29-22-02-26.backup', 'rb').read())

    f.seek(0, os.SEEK_END)
    while True:
        if (chunk := read_chunk(f)):
            print(f'[{hex(f.tell())}] Found chunk of size: {hex(len(chunk))}')
        else:
            sticker_len, sticker_id, chunk = find_sticker(f)
            print(f'Found sticker (len={sticker_len}) idx={sticker_id}')
            print(f'[{hex(f.tell())}] Found chunk of size: {hex(len(chunk))}')
