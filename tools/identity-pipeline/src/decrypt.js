import 'dotenv/config'
import * as fs from 'fs'
import * as path from 'path'
import nacl from 'tweetnacl'
import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305'

function aeadOpen(key, nonce, aad, ciphertext) {
    const aead = new ChaCha20Poly1305(key)
    return aead.open(nonce, ciphertext, aad)
}

function b64(s) { return Buffer.from(s, 'base64') }

async function main() {
    const outDir = path.join(process.cwd(), '.out')
    const encMeta = JSON.parse(fs.readFileSync(path.join(outDir, 'bundle.enc.meta.json'), 'utf8'))
    const enc = fs.readFileSync(path.join(outDir, 'bundle.enc'))
    const kp = JSON.parse(fs.readFileSync(path.join(outDir, 'enc_keypair.dev.json'), 'utf8'))

    const senderPub = b64(encMeta.cekWrapped.senderEphemeralPubKey)
    const nonceWrap = b64(encMeta.cekWrapped.nonce)
    const wrapped = b64(encMeta.cekWrapped.wrapped)
    const recipientSecret = b64(kp.secretKeyBase64)

    // Unwrap CEK
    const cek = nacl.box.open(wrapped, nonceWrap, senderPub, recipientSecret)
    if (!cek) throw new Error('Failed to unwrap CEK')

    // Open AEAD bundle
    const nonce = Buffer.from(enc.slice(0, 12))
    const ciphertext = Buffer.from(enc.slice(12))
    const aad = Buffer.from(
        String(encMeta.aad.chainId) + encMeta.aad.registry + encMeta.aad.user + encMeta.aad.identityCommitment
    )
    const clear = aeadOpen(cek, nonce, aad, ciphertext)
    if (!clear) throw new Error('Decryption failed')
    fs.writeFileSync(path.join(outDir, 'bundle.decrypted.json'), Buffer.from(clear))
    console.log('Decrypted bundle written to .out/bundle.decrypted.json')
}

main().catch((e) => { console.error(e); process.exit(1) })
