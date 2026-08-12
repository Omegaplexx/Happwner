package com.happwner.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

// The hand-written ChaCha20-Poly1305 in HappCrypto, against vectors from pyca/cryptography: the first is
// RFC 8439 2.8.2 and reproduces the ciphertext printed there, which is what makes the other eight sound.
class ChaChaPoly1305Test {

    private class Vector(
        val name: String,
        val key: String,
        val nonce: String,
        val aad: String,
        val plaintext: String,
        val ciphertextWithTag: String
    )

    private fun hex(s: String): ByteArray {
        if (s.isEmpty()) return ByteArray(0)
        return ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte() }
    }

    private val vectors = listOf(
        Vector(
            name = "rfc8439_2_8_2",
            key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            nonce = "070000004041424344454647",
            aad = "50515253c0c1c2c3c4c5c6c7",
            plaintext = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            ciphertextWithTag = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ),
        Vector(
            name = "random_0_pt0_aad0",
            key = "66bcbecd6b65a7872acfd6cb9e7951dd1affc313c18ea71af95bf1a3890c60dd",
            nonce = "952b890200bc365393141e53",
            aad = "",
            plaintext = "",
            ciphertextWithTag = "9bb393ed837a2f5404ebf2c5c5ebf567"
        ),
        Vector(
            name = "random_1_pt1_aad0",
            key = "23ef5b304ab89a22f6d70996a569c8c9b090e60cfb2ef83d957e42aa26f45dd6",
            nonce = "22f1175188784e576ee89d6b",
            aad = "",
            plaintext = "4a",
            ciphertextWithTag = "58e7aca8f4d770db7d169baab896d4988f"
        ),
        Vector(
            name = "random_2_pt0_aad13",
            key = "f29c74c512aaacc8daa37286d0d82abff3ba28f9439a84aac7b7fb4b18f22d86",
            nonce = "e3c55769ded309035340bd00",
            aad = "72f7099b4a0b9f76fa7d856daa",
            plaintext = "",
            ciphertextWithTag = "9e7bbf6bb7c01e9668241ead0dba4a9d"
        ),
        Vector(
            name = "random_3_pt63_aad17",
            key = "c51e0ee147ad0587acf4abdd314736f09481eb77c12c65fa1ae730dc2c4a4905",
            nonce = "9fc0b0c946d5df77370e60f2",
            aad = "307e46215585e832e991415254c6bdbb9e",
            plaintext = "ae04b38cccd4bc970e7aa7213c358a6c9edfdf64964d89e31d933fd3b9b2805975c2f8e0a493d162570b23ec97c0d3e23b1ad2c0778ff704195f9a493d8533",
            ciphertextWithTag = "933f10a497d13145fa8c522e8a5931b07efbd5fe98fd766b8d555a682d102c94e904252a24740a965282e82f1f8d3276b045a4ef58b672c72ff6d71f1317320afbf58040e9a64a2e116ff252f79476"
        ),
        Vector(
            name = "random_4_pt64_aad0",
            key = "1030822c3d499055cb033bd6b78ebe37b136259b3b6153404734ebb500370792",
            nonce = "ec0dfb67689ebe55d6749206",
            aad = "",
            plaintext = "1c70046db2a1a8036414585488255017809f4140208288eda90b12725cdef7331a3c69033a67d7b23e8bc6a8215b4f3f161a7931202641050ab8ca3f8a5cfb72",
            ciphertextWithTag = "c1e41b2b27cf1f0f62b74f880efa7fa7405e02b03a2c78e5d19ec63cc50ad4eba10b3730c77394e26a4ea64c20f4d483d0ef49be45050c6381346552b6aa8dd4bb28b13bb42db5cee9af8fbdbb324aad"
        ),
        Vector(
            name = "random_5_pt65_aad32",
            key = "a09f72872ea33ee29e8c061c8d19c3e9f9fd9790efd6bc6a000014b2bbf95e8f",
            nonce = "f4b25ead026aeff9a58c152a",
            aad = "c07b611078a908cf7ddecb3e648d06b164a86343e3074f929693e6dc48886418",
            plaintext = "87b6a47a8f32c02b6337edd3f09f1851a029ef2d823f616a78bbca58aedf2b40d1123d7585908079eb9d072014527cf38a213751bad988970e5f0ba5fdee1b2525",
            ciphertextWithTag = "a2cc0010ae053076c7d39b14475b88e7ac8579dff21359d49b4d3e59cfbc1ad9a8c5b2cd8982456d61f100f06bae9fa02d1ad7c5b2d038c30322241e0dbfccf15ed38261ed352ad6d3ccd301a0f4ee0bdd"
        ),
        Vector(
            name = "random_6_pt200_aad7",
            key = "15cb2fe6abbc5068e0e0220fe5b71044a23948dda3639065fd1fae6e2b6febaf",
            nonce = "c8b3f05f669c9d2bbea920aa",
            aad = "e19f467ef8e31c",
            plaintext = "217e32365ae4032d89cf1034adf5325530bb4bbf5cc2e5e31feeb0a15e9135d903f238e6a79587751f524455b236eec14d7b2f9169f7f0022a48e6a7fc13aaf62c43a61da41f6c9b2e0b6589fcde143a6f683c20108e2d0122740334980332ec1ff9f15b985bac6f3b648f5185ff7e2ab840796d98aa6227033217263fd38958eada673699e9c96fa8ba2775696bfbd84f38f4a8eeb324a4708e49512980cb2590d4644cbaeb81166b7d08933def02903e7c009f9a215400c25c08738f0e2ae4c1520a33e30f4cd0",
            ciphertextWithTag = "1ec9a549177097e7a8c78813c688a56d31407a48c1b3e739e1b01ff31a1d354f6412ef031e88c41c16a5575a46ca337f8af98ef7b471e0fc656c09a1e3023f8729478d7e97aa8bc4e9cd37a760a6b1a99f194d22fb6ff1903fa974bd2e367db8c2e832a24eb495ad0c4e21868c8beb662be7673db475a4dc44832d63988177802414d47efa56825938127473fa98bb2d82fbc6e89923c2b5f1fe9da8ff5d90b65e8cf8a94cfbc4d2ba4d04964cd0b9dd7a4faf8805c60a2ca4149b556ebb0f270326bab8f9a216143be9b3cb232127b175d7b61490ba87f8"
        ),
        Vector(
            name = "random_7_pt1000_aad64",
            key = "6a631a96c185b50c057e4380efed310dd227ab83e85baf9f31a1e99002a6b156",
            nonce = "d8849b6e926729a5fc28874e",
            aad = "1b07db39591a9f23456dfa8da953f61da59e48763edb119dbcd5f4afcd091e4b0c26611d9b50d820ec3e28b7038896ec00e9b960a53a8557d1fc909c6c805f00",
            plaintext = "e3442597d52e6200fce9ea427e96c339d8e2363ef0637c53fe616eddea91f2f9b357202100e46a4f404c7d3eff2f8956e126c77fa0b4139926b9893a13692b18953f5b760b3d167fdc944613527642ae44d30649b28efd1333241403bd4e980ef0d4e7a717a0f52d1279e1f9b79ea998c7b9cbac3b9bb488bebb000844d97d8ff4ec6e901f2014ed0a3c24f6d61f018a75456930de03ebaada39afbd9c3b2d6a9ae0ec74c8fadedd720e4610157e82b1d95ceab15ddc51c1a2f482de4dab80ac6db7b73b3b9b984fa284f1bd9476ca0f708fcc0fcc66b5eb7fbc68bdddcdbd62468098c09915d7233cd8c89f66f857fbbac4f51ff8645a0716860255a5bd7391565605c7b560c0e5d1d5b061f0ea47d95c21191ac66f3c397086b4cccec839943ab9bf9f5eded7deca8bccd9f7a036f4d7398d9f9e3fbd637c82a2f16b795a7b3f9a201f6f5c2fc30f5805b98883aba5ee54578369a5415f0b8280da7055f866cf1f46d6a1ae88bb0e758ae99a7f5cecdb14e88914348e93ed891a3b5988332a583350f941ffa9dee3c2b12ab4fa565d03928b2667f88684a7f3bf1cdd4d99dd5edb00acbe04439daf93d0551b6c9f9c64d492b3db1ce46ed733858308150769d5699e8ef846fefac10e3b8390f0ea8a75e1f0615220b2d454a6a336a21b815b853b040044e7781a41b10921257ff2b4523e746d8f6d8aa25bf359430278bd8c47f2f1b94a8555ee64f94183ea60154c1ee9b70b13f8e887ab9c21d0837950068275a77430a0917dda59f123390cf97aab0ade6d0cbd3aa349a9e9c9b2461a73ffcf64f9a942bb8b9192ea024915e5ce4b24990fc96ca4341dd6df520a0934cd1639bc0dfdb6f74b4e432e4fdf654117d0698d43902c15b3c0896e5afabf427eeee5967b564b355e4666bace1a83a1ff1bc52379164d69f203aa37fee3e1eb002115848a1d6213761421bb47287b6824d28405c0c16b256bae5f94e6628140729aa3ac83c1f64249b3bfdbf9489b51cf1e35e509f3aac8da0d7afb7ff95657f9e5b33d1c5c8e22e107a81b3ab8e97ebeda4f2e41b539cc1464a50ba7eab1840871926f141b92cd96b98ffd751bba020b4268ec8893b8fdc5aff7997041cd51bfd7aa6b5faac3cf258af25e7c7b48caeb11a72f91d3ce31c1f2b6c87eeb617d7de680c0d9ac1e9a093ea9cc2261548b674b8da63dc8bc5e177dffb3c7eae20afd6d0c8c00e1f7cb243dd04f9c42ff5107ddcf4cfff8485ced55534200f53f4e7c7a9f387cfc328d62be395775c34fdc7ab6abb4ac9140a7d64a3f58081b9496a59d4f2ccfee15fae830d0a3fb356a7faf711942e0f164daec147725df6b76e9e96cf0c9bd41dd25df27f7bb8f567eb717d196b90d6808b7a7221eddc09c63bf28da0e2b3d8894575f",
            ciphertextWithTag = "da6f67638728799d47ad4f61f1732b6b7eecff5a9c0d892394b70c091da75a385f9153345b8432196554bcd1bb29189626174a57cfb0af2439730524835aed7ef858171778365f3fb1df4210fd3fdd016b86ce3b437bf10fad8c0a01f8da194a061f806e7403d18d635756558da84a6bc3235ac26148a9ab0108be805d80d54d534d079c16f091e2604a55548576be6e159b849865ee3a6f4b936f82feb220f02ec14b1c8de0431f781e874a641f620bfc86193df7e85f15f1b15bfe1efb761f7d08b7f8bd2051f148d8c5bf26c97023c45ef4e1f7a03045d699db623882803c331c05ff73aa8f4978896f17819492ff5564440a1c7ab4e8e7c6ae7003b590332bf9e8ba499f82addde84a7c8fad2c35ad076c252823eac15c7ab5ed160cfe334f0914e915dc93946dba9dc97e44b88b6f76f792a426ce0d73725933b3b25b5696e80cde5661b23dadaef4fa512b833789da3e0816df6f35bec9cfbb49f6049cd6cb9ae815ce47bf8baff677c3d4421681ce29c17af7ff55d90da7ccd36c617964e27d10f15be025117f028e05dec043a3c5c3b8a9ee5ed755009bf03c9adbc72c7f644e9c0eb456a1139f42940df91d2bccc5c1f553a7e73c4dfb2d02784b6df8f93031734ec9a31b18b2d51cdbec5027b4b4c1aa118a08ec97b06f823e825823935cd90a37764488874e6375ea1e6b7e63cf8410ae84c571a8d2ca6b778993eaf14c92366da4b2106658ded5e6705e4760a1d0347b9da03d6327aa9f0b63a2b0e19b06fe1878dbfadd27094d4e865fe88e5f6073dd5d04afc102d21fed89eb52221d39d88e52d2865150072a16ea10eaedb50c3b0f19e0feac53f5d2e0c1961ef09fdc37e5081bc68cefcc2f77c12f9504ab571bb11ba23746a9d28592ea3a316f2902197426e4994aee4608c60757a5a6e755280bbb61c15c32eb8e4d68294c19e49e863fbe761269e2a73891e5f3dd9f0ae8a623dc30320d645c3cc535ddb795786896ccb12deeb7194b38a048df41b5148de50eb16aee8cf02c06f06fbd65aecac8899fdb3db426e4e9fa249552614386a8486b4d35af92b30298e0af33d73e555e1309386994e8a04c2103287431b55d3be469ae930f0b15c8860f9e5353b308ba181255fbca0621ad3fd75b8d25ab2144fbcb001b80ca737f36aa7f84124bf44fd6c6f914e902750ff6fada799049c95245a77f60044da674dec6d04bff1b0348f009d0ada14c9ff8345b52cc03a9c2e8b5913f7eeef29cf2223e4a87baaed759c8c62d24e5186903d1dd3c7239738ab6b9e26aae8adaa22d1a56c71f26f9e7c313c8ec064ceb5418cb2351b7b84d8fd857645327f9f7dc4f6877564f221c100f37b624536b8a3fe62f1eec577389dea9489a209ba09068ee55dd5271103d23ac0e7e8943362f57740846c513c3df5bba0b6826e8"
        ),
    )

    // The private AEAD inside HappCrypto, reached without widening it.
    private fun aeadDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        val cls = Class.forName("com.happwner.crypto.HappCrypto\$ChaCha20Poly1305")
        val instance = cls.getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
        val m = cls.getDeclaredMethod(
            "decrypt", ByteArray::class.java, ByteArray::class.java,
            ByteArray::class.java, ByteArray::class.java
        ).apply { isAccessible = true }
        return try {
            m.invoke(instance, key, nonce, aad, ct) as ByteArray
        } catch (e: java.lang.reflect.InvocationTargetException) {
            // Unwrap, so a refused tag arrives as the exception the code threw
            // rather than as a reflection wrapper around it.
            throw e.cause ?: e
        }
    }

    private fun open(v: Vector, ct: ByteArray = hex(v.ciphertextWithTag)): ByteArray =
        aeadDecrypt(hex(v.key), hex(v.nonce), hex(v.aad), ct)

    @Test
    fun `every vector decrypts to its plaintext`() {
        for (v in vectors) {
            assertArrayEquals("vector ${v.name}", hex(v.plaintext), open(v))
        }
    }

    @Test
    fun `the RFC 8439 vector is among them and matches the published ciphertext`() {
        val rfc = vectors.first { it.name == "rfc8439_2_8_2" }
        assertTrue(
            "the published ciphertext must be what the reference produced",
            rfc.ciphertextWithTag.startsWith("d31a8d34648e60db7b86afbc53ef7ec2")
        )
        assertArrayEquals(hex(rfc.plaintext), open(rfc))
    }

    @Test
    fun `a flipped ciphertext bit is refused`() {
        for (v in vectors) {
            val ct = hex(v.ciphertextWithTag)
            if (ct.size <= 16) continue          // no ciphertext to disturb
            for (bit in 0 until 8) {
                val bad = ct.copyOf()
                bad[0] = (bad[0].toInt() xor (1 shl bit)).toByte()
                try {
                    open(v, bad)
                    fail("vector ${v.name}: a flipped ciphertext bit was accepted")
                } catch (_: Exception) {
                }
            }
        }
    }

    @Test
    fun `a flipped tag bit is refused`() {
        for (v in vectors) {
            val ct = hex(v.ciphertextWithTag)
            for (bit in 0 until 8) {
                val bad = ct.copyOf()
                bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor (1 shl bit)).toByte()
                try {
                    open(v, bad)
                    fail("vector ${v.name}: a flipped tag bit was accepted")
                } catch (_: Exception) {
                }
            }
        }
    }

    @Test
    fun `changing the aad, nonce or key is refused`() {
        val v = vectors.first { it.aad.isNotEmpty() }
        val ct = hex(v.ciphertextWithTag)
        val badAad = hex(v.aad).copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val badNonce = hex(v.nonce).copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val badKey = hex(v.key).copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        for ((label, call) in listOf<Pair<String, () -> ByteArray>>(
            "aad" to { aeadDecrypt(hex(v.key), hex(v.nonce), badAad, ct) },
            "nonce" to { aeadDecrypt(hex(v.key), badNonce, hex(v.aad), ct) },
            "key" to { aeadDecrypt(badKey, hex(v.nonce), hex(v.aad), ct) }
        )) {
            try {
                call()
                fail("a changed $label was accepted")
            } catch (_: Exception) {
            }
        }
    }

    @Test
    fun `truncated input is refused rather than read past the end`() {
        val v = vectors.first { it.plaintext.isNotEmpty() }
        val ct = hex(v.ciphertextWithTag)
        for (cut in listOf(0, 1, 15, 16)) {
            if (cut >= ct.size) continue
            try {
                open(v, ct.copyOf(cut))
                fail("a ${cut}-byte input was accepted")
            } catch (_: Exception) {
            }
        }
    }
}
