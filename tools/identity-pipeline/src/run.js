import 'dotenv/config'
import dotenv from 'dotenv'
import { randomBytes } from '@stablelib/random'
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305'
import { sha256 } from '@noble/hashes/sha256'
import nacl from 'tweetnacl'
import { buildPoseidon } from 'circomlibjs'
import * as fs from 'fs'
import * as path from 'path'
import pinataSDK from '@pinata/sdk'
import { IncrementalMerkleTree } from '@zk-kit/incremental-merkle-tree'

// NOTE: This helper now demonstrates real X25519-style keypairs (via tweetnacl.box),
// Poseidon hashing (via circomlibjs), and a simple Merkle root (Poseidon hash chain) for demo.

function aeadEncrypt(key, nonce, aad, plaintext) {
    const aead = new ChaCha20Poly1305(key)
    return aead.seal(nonce, plaintext, aad)
}

function toHex(arr) {
    return '0x' + Buffer.from(arr).toString('hex')
}

function makePublicIndex({ chainId, registry, user, identityCommitment, encPubKey, anchors, privateBundleCid }) {
    return {
        version: '1.0',
        chainId,
        registry,
        user,
        did: `did:pkh:eip155:${chainId}:${user}`,
        identityCommitment,
        encPubKey,
        verification: { face: false, aadhaar: false, income: false, level: 0, updatedAt: Math.floor(Date.now() / 1000) },
        anchors: anchors || [],
        privateBundleCid,
        history: []
    }
}

async function main() {
    let pinataJwt = process.env.PINATA_JWT
    // Fallback: look for a .env in parent folders if not set
    if (!pinataJwt) {
        const candidates = [
            path.join(process.cwd(), '.env'),
            path.resolve(process.cwd(), '..', '.env'),
            path.resolve(process.cwd(), '../..', '.env')
        ]
        for (const p of candidates) {
            if (fs.existsSync(p)) {
                dotenv.config({ path: p })
                pinataJwt = process.env.PINATA_JWT
                if (pinataJwt) break
            }
        }
    }
    if (!pinataJwt) throw new Error('Missing PINATA_JWT in env')

    // Fake values for demo purposes
    const chainId = 11155111
    const registry = '0xRegistryAddress'
    const user = '0xUserAddress'
    const identityCommitment = '0x' + '11'.repeat(32)
    // 1) Generate an X25519-like encryption keypair (nacl.box uses Curve25519)
    const encKeyPair = nacl.box.keyPair()
    const encPubKey = Buffer.from(encKeyPair.publicKey).toString('base64') // publishable

    // 2) Build Poseidon leaves and a real Poseidon Merkle root
    const poseidon = await buildPoseidon()
    const F = poseidon.F
    // Example attributes
    const nameValue = 'Alice Example'
    const dobValue = '2003-01-01'
    const birthYearValue = 2003n
    const incomeValue = 800000n // integer

    // Salts per attribute (removed unused salt)
    const saltName = randomBytes(32)
    const saltDob = randomBytes(32)
    const saltBirthYear = randomBytes(32)
    const saltIncome = randomBytes(32)
    // Encode value to a field element by base-256 packing the ASCII bytes
    const packAsciiToField = (str) => {
        let acc = 0n
        for (const ch of Buffer.from(str, 'utf8')) {
            acc = acc * 256n + BigInt(ch)
        }
        return acc
    }
    const dobField = packAsciiToField(dobValue)
    const nameField = packAsciiToField(nameValue)
    const birthYearField = birthYearValue
    const incomeField = incomeValue

    const saltNameField = BigInt('0x' + Buffer.from(saltName).toString('hex'))
    const saltDobField = BigInt('0x' + Buffer.from(saltDob).toString('hex'))
    const saltBirthYearField = BigInt('0x' + Buffer.from(saltBirthYear).toString('hex'))
    const saltIncomeField = BigInt('0x' + Buffer.from(saltIncome).toString('hex'))

    const nameLeaf = F.toObject(poseidon([nameField, saltNameField]))
    const dobLeaf = F.toObject(poseidon([dobField, saltDobField]))
    const birthYearLeaf = F.toObject(poseidon([birthYearField, saltBirthYearField]))
    const incomeLeaf = F.toObject(poseidon([incomeField, saltIncomeField]))

    const leaves = [nameLeaf, dobLeaf, birthYearLeaf, incomeLeaf]
    const depth = 20
    const zeroValue = 0n
    const tree = new IncrementalMerkleTree(
        (values) => F.toObject(poseidon(values)),
        depth,
        zeroValue,
        2
    )
    for (const leaf of leaves) tree.insert(BigInt(leaf))
    const merkleRoot = tree.root

    // Build proofs for each attribute by index
    const proofFor = (index) => {
        const p = tree.createProof(index)
        return {
            pathElements: p.siblings.map((s) => '0x' + BigInt(s[0] ?? s).toString(16)),
            pathIndices: p.pathIndices.map((i) => Number(i))
        }
    }
    const proofs = {
        name: proofFor(0),
        dob: proofFor(1),
        birthYear: proofFor(2),
        income: proofFor(3)
    }

    // 3) Build a tiny private bundle JSON (no real PII)
    const bundle = {
        version: '1.0',
        user,
        encPubKey,
        secrets: {
            attributes: [
                { name: 'name', value: nameValue, saltHex: toHex(saltName), poseidonLeaf: '0x' + BigInt(nameLeaf).toString(16), sha256Leaf: '0x' + Buffer.from(sha256(Buffer.from(nameValue))).toString('hex') },
                { name: 'dob', value: dobValue, saltHex: toHex(saltDob), poseidonLeaf: '0x' + BigInt(dobLeaf).toString(16), sha256Leaf: '0x' + Buffer.from(sha256(Buffer.from(dobValue))).toString('hex') },
                { name: 'birthYear', value: birthYearValue.toString(), saltHex: toHex(saltBirthYear), poseidonLeaf: '0x' + BigInt(birthYearLeaf).toString(16), sha256Leaf: '0x' + Buffer.from(sha256(Buffer.from(birthYearValue.toString()))).toString('hex') },
                { name: 'income', value: incomeValue.toString(), saltHex: toHex(saltIncome), poseidonLeaf: '0x' + BigInt(incomeLeaf).toString(16), sha256Leaf: '0x' + Buffer.from(sha256(Buffer.from(incomeValue.toString()))).toString('hex') }
            ]
        },
        documents: [],
        merkle: { leaves: leaves.map((x) => '0x' + BigInt(x).toString(16)), root: '0x' + BigInt(merkleRoot).toString(16), treeDepth: depth },
        attrProofs: {
            name: proofs.name,
            dob: proofs.dob,
            birthYear: proofs.birthYear,
            income: proofs.income
        },
        vcs: [],
        audit: { createdAt: Math.floor(Date.now() / 1000), updatedAt: Math.floor(Date.now() / 1000) }
    }

    const bundleJson = Buffer.from(JSON.stringify(bundle))

    // AEAD encrypt the bundle JSON
    const aad = Buffer.concat([
        Buffer.from(String(chainId)),
        Buffer.from(registry),
        Buffer.from(user),
        Buffer.from(identityCommitment)
    ])
    const cek = randomBytes(32)
    const nonce = randomBytes(12)
    const ciphertext = aeadEncrypt(cek, nonce, aad, bundleJson)

    // 4) Wrap CEK to the user's enc public key (demo using nacl.box)
    // In practice, you'd store the wrapped CEK in metadata; here we just show that wrapping works.
    const recipientPub = encKeyPair.publicKey
    const senderKeyPair = nacl.box.keyPair() // ephemeral sender
    const wrapNonce = randomBytes(24)
    const wrappedCek = nacl.box(cek, wrapNonce, recipientPub, senderKeyPair.secretKey)
    const cekWrapMeta = {
        alg: 'nacl.box.x25519xsalsa20poly1305',
        recipient: encPubKey,
        senderEphemeralPubKey: Buffer.from(senderKeyPair.publicKey).toString('base64'),
        nonce: Buffer.from(wrapNonce).toString('base64'),
        wrapped: Buffer.from(wrappedCek).toString('base64')
    }

    // Initialize Pinata client
    const pinata = new pinataSDK({ pinataJWTKey: pinataJwt })
    try {
        await pinata.testAuthentication()
    } catch (e) {
        const status = e?.response?.status
        const data = e?.response?.data ? JSON.stringify(e.response.data) : String(e)
        throw new Error('Pinata authentication failed' + (status ? ` (status ${status})` : '') + ': ' + data)
    }

    const rootDir = path.join(process.cwd(), '.out')
    if (!fs.existsSync(rootDir)) fs.mkdirSync(rootDir)
    // DEV-ONLY: persist the encryption keypair so the decrypt step can unwrap the CEK.
    // In production, you would NEVER store the secret key like this.
    const devKeypairMeta = {
        note: 'DEV ONLY - do not commit or use in production',
        publicKeyBase64: Buffer.from(encKeyPair.publicKey).toString('base64'),
        secretKeyBase64: Buffer.from(encKeyPair.secretKey).toString('base64')
    }
    fs.writeFileSync(path.join(rootDir, 'enc_keypair.dev.json'), JSON.stringify(devKeypairMeta, null, 2))

    const bundlePath = path.join(rootDir, 'bundle.enc')
    // Persist encryption metadata for bundle CEK
    const bundleEncMeta = {
        aead: 'chacha20poly1305',
        aad: {
            chainId: chainId,
            registry,
            user,
            identityCommitment
        },
        cekWrapped: cekWrapMeta,
        nonce: Buffer.from(nonce).toString('base64')
    }
    fs.writeFileSync(bundlePath, Buffer.concat([nonce, ciphertext]))
    fs.writeFileSync(path.join(rootDir, 'bundle.enc.meta.json'), JSON.stringify(bundleEncMeta, null, 2))

    const bundleCid = (await pinata.pinFileToIPFS(fs.createReadStream(bundlePath), {
        pinataMetadata: { name: 'bundle.enc' }
    })).IpfsHash

    // Create public index JSON pointing to the encrypted bundle
    const publicIndex = makePublicIndex({ chainId, registry, user, identityCommitment, encPubKey, anchors: [], privateBundleCid: `ipfs://${bundleCid}` })
    const indexPath = path.join(rootDir, 'index.json')
    fs.writeFileSync(indexPath, JSON.stringify(publicIndex, null, 2))
    const indexCid = (await pinata.pinJSONToIPFS(publicIndex, {
        pinataMetadata: { name: 'index.json' }
    })).IpfsHash

    console.log('bundleCid:', bundleCid)
    console.log('indexCid:', indexCid)
    console.log('Now call setMetadataURI(user, "ipfs://' + indexCid + '") from your REGISTRY_MANAGER.')
    console.log('Demo enc pubkey (base64):', encPubKey)
}

main().catch((e) => {
    console.error(e)
    process.exit(1)
})
