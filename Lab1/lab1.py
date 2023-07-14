#M0.0
import hashlib
print(hashlib.sha224(b"you made it").hexdigest())

#M0.1
from Crypto.Hash import SHA256
print(SHA256.new(data=b'hi').hexdigest())

#M0.2
string = b'LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteurs.'
splits = [string[i : i + 16] for i in range(0, len(string), 16)]
concat = bytes([l[-1] for l in splits])
print(SHA256.new(data=concat).hexdigest())

#M1.0
print(bytes.fromhex('596f752063616e206465636f646521').decode())

#M1.1
print("ጷ뼯쯾".encode().hex())

#M2
b = bytes.fromhex('210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002')
for key in range(256):
    if key != 103:
        continue
    mes = [b[i] ^ key for i in range(len(b))]
    try:
        print(key, bytes(mes).decode())
    except:
        print(key)

#M3
plain = 'Pay no mind to the distant thunder, Beauty fills his head with wonder, boy'
key = 'bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f489f3454bbe1cab4510ccb979013277a7bf'
bplain = plain.encode()
bkey = bytes.fromhex(key)
bcipher = [bplain[i] ^ bkey[i] for i in range(len(plain))]
print(bytes(bcipher).hex())

#M4
def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))

t1 = '9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0'
t2 = 'b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4'
c1, c2 = bytes.fromhex(t1), bytes.fromhex(t2)
c = xor(c1, c2[:len(c1)])
it, slice, res = 0, 'flag{'.encode(), ''
while it < len(c1):
    cur = xor(c[it : it + min(len(c1) - it, 5)], slice)
    res += cur.decode()
    it += 5
    slice = cur
print(res)

#M5
from itertools import cycle

def cycxor(a, b):
    return bytes([i ^ j for i, j in zip(a, cycle(b))])

CHALLENGE_CIPHERTEXT = "4d68f21bf515dce57ee78a66724c4d9f5416fadc8d417652d8cbe1ce8080fc132bec643cc30460f9561669cc16d2786af846a12c611c6dc150504a22b18c95c9e34dd8f0efb1aa0fe0ec8a996b03ee56b27bac5bbc70413a5fa29de92dfee2802735e334c44f026e6cbbf9b40f65a0faf3bf11ddfb75083b417eb306f317c4f07bf88c27714555994045a9c8cf517042dccaf4c98e82a50336bc7836911325ea4b107e8942ce752fb450ba29660024da43045725ba8c9fc0ea52d6e0eeebf940effd8a997c03e405bb70e25eb138153d5ca29cf22dfee6837e23ac2dc5161c723ebbbce71862b3bfeabb0698a86a097e0465a012ea0dc4ea73fb9b746409559f5953fa899a42224fc4dbb5c4869eb41530e86921c55729e01e1d3bca59ca6562b646f86e650061c740044d6db6dfd4d1fb4099feefabbe5be9be80df281fe940f77ee940b23f473614a29cf22db0ad836637ab7fc259197473b1f5f71a63e5b8fdfe16c6ed7f157e4026b318ba0dcde132f48b77784c4b82524efd898054225a8cd3fac9808fb0002afd6e3cc51e23ae4d0679da42cf647aac5cbb20320b6dc54d415163ffcd8785e050dafaa6e5bc4ee2f6cfda6707f448b935ef58ab7057371ae39cee29bde6836374b436d55e55676cbaa4e11e63a6a3b8bf0cd5e46712725728f218f314cce873e58e7e3c094e9e5244ec898e127054d8d1e7879c9aae1523f12c3ad80728eb4c5376c855ce7961bd15bc2f614866d0404a0338acc99089b351d1fbf9e5b44af5f680dd2806e05cf774e055aa27152652e7c8fe2dbaf885733dac31815913216ab7b0b41768abbdecb642dbee3e0875406fa402fe0cc4e832e58d737f5b4ad81742e1cccf596348c5cdfececf8ba4112ff56238c51e2fe01e1a75df59ca666aab15b8217d036ddb42044522ad8c87d1e14cd7f5f9e5b649a1fd87d87a0ae251b267ff19b13854261ae39aff68ace8966235b73ac5161c6f3eabbdf15b6eacaaf0bb10c0ed6615350472ba0eba0ad1f67bf98574305a5199425aed898d57224fc4ccf0c2cf8db41130fd6f2dd40533ae521c75ce16c9622fb55aa62b320e6bc705504b28ffc98cc4fe4cd7f3feacb641a1ea80996a0ea156a276ef5cb623532756acc8ee20bbe3ca2720ab3a81521c726abebbf71e7ee5b8fdaa15d1ed7041784b68a10ef90cd1ed64f2c268734a4c844553e7ca8a412254ca9ee1cf8aceaf0430f5623ec25721fc5b5377c05dc37c76f841bb6e700d24d850485724afc091d6b34adfb2feadbc0fedfb81de7c03a14ab135f851a0705e3743f587e82cf0ad926f21b07fc75f1b6577b1b2b41662b7bfb8ac07c4ed7f157e4026a11fe810cbe361b78c66625b56814416edc6985c224fc4dbb5d7809daf1920f06979dd122ee94a1b688959c0307bb050f425771173da57400f6dacc59ac6f605cef7aaa6b841a1ea8ed26d4bf54db235eb4ba031413749f6c8f927b3e0896974a736d75f066e6cffbaf25b6ca9b6b8aa0ad1a87a08685067bc08ff0a8ba466ff8727624c58855858a9dd875b711bd8dbe6d3cf99b30229ef2c30c25734e65f073bc05086712faa50a42b731c61d10557573fb6c29385fc46dae7f8b6f946efbe9bd16d4bf149b67ce24da028417e1ae386fe68aae5832730aa2cd5571b627bffb7f10f7aa0bff6fe01dbfa6c04685469bc0ff317c2a471ff8375714a4d934545a9c09c12631bc1cbf9d3869eb01562f36a79c51f25ae551662de59d4742fb450ba2966002895514c466db4c98dd2fc57ddb2e6a0ad5be4ec9c997f02ed49f779e557a07040221aeb86ba3cb6e8c67435ae3a814114783ea8bce0132da7b5ecb642dbeb7d14695663bc08ff0a85eb74b7966f75094a82455fe7cec1126457cdd9eec19d8bad0527f26f2091162eef520a68c045867f61f847b13e770970d041044828a6df80d7f644d4ef"
valids = set([b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'r', b's',
             b't', b'u', b'v', b'y', b'z', b'q', b'w', b'x', b' ', b'.', b',', b'{', b'}'])

cipher = bytes.fromhex(CHALLENGE_CIPHERTEXT)
groups = [cipher[i : i + 120] for i in range(0, len(cipher), 120)]
fs = [[g[i] for g in groups[:-1]] for i in range(120)]
for i in range(len(groups[-1])):
    fs[i].append(groups[-1][i])
fs2 = [[g[i:i + 2] for g in groups[:-1]] for i in range(119)]
for i in range(len(groups[-1]) - 1):
    fs2[i].append(groups[-1][i:i + 2])

#b'@&' appears twice in 1st 2 letters
#b'~\xb3 appers twice in 2nd 2 letters, \xf2 appears twice as last letter

allPoss = []
for i in range(120):
    possible = set()
    for k in range(256):
        for c in fs[i]:
            cur = c ^ k
            #print(bytes([cur]))
            if bytes([cur]) not in valids:
                break
            if c == fs[i][-1]:
                possible.add(k)
    allPoss.append(possible)

def fix(index, char):
    found = 0
    for poss in allPoss[index % 120]:
        if bytes([fs[index % 120][index // 120] ^ poss]) == char:
            found = poss
            break
    allPoss[index % 120] = set([found])

fix(1313, b'h')
fix(1315, b'o')
fix(1318, b'u')
fix(1323, b'c')
fix(1205, b'n')
fix(728, b'i')
fix(1349, b'e')
fix(1351, b'u')
fix(186, b'o')
fix(468, b'e')
fix(467, b'u')
fix(466, b'q')
fix(465, b'e')
fix(464, b'r')
fix(13, b'e')
fix(14, b't')
fix(15, b'i')
fix(859, b'c')
fix(860, b'e')
fix(23, b'i')
fix(34, b'h')
fix(35, b'e')
fix(36, b'r')
fix(1019, b' ')
fix(1021, b'i')
fix(1001, b'h')
fix(1363, b'i')
fix(1364, b's')
fix(1372, b'e')
fix(1373, b'a')
fix(1374, b't')
fix(1375, b'e')
fix(1377, b' ')
fix(1365, b' ')
fix(1368, b' ')
fix(47, b'e')
fix(694, b'e')
fix(697, b'a')
fix(698, b't')
fix(700, b'd')
fix(701, b' ')
fix(910, b'e')
fix(911, b' ')
fix(913, b'e')
fix(915, b'g')
fix(917, b'h')
fix(1052, b'o')
fix(1049, b't')
fix(1048, b's')
fix(1047, b'e')
fix(1045, b'a')
fix(1044, b'e')
fix(1040, b'e')
fix(1039, b'h')

provision = ''
for i in range(len(cipher)):
    if len(allPoss[i % 120]) == 1:
        for k in allPoss[i % 120]:
            provision += bytes([cipher[i] ^ k]).decode()
            if provision[-1] == 'm':
                pass
                #provision += str(i)
    else:
        provision += '_'
print(provision)