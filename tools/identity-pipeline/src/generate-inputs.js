import * as fs from 'fs'
import * as path from 'path'

function hexToBigInt(hx) { return BigInt(hx) }

function packAsciiToField(str) {
    let acc = 0n
    for (const ch of Buffer.from(str, 'utf8')) acc = acc * 256n + BigInt(ch)
    return acc
}

function writeJSON(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)) }

async function main() {
    const outDir = path.join(process.cwd(), '.out')
    const bundle = JSON.parse(fs.readFileSync(path.join(outDir, 'bundle.decrypted.json'), 'utf8'))
    const root = bundle.merkle.root
    const depth = bundle.merkle.treeDepth

    // Helper to find attribute
    const getAttr = (name) => bundle.secrets.attributes.find(a => a.name === name)
    const toField = (a) => ({
        valueField: a.name === 'name' || a.name === 'dob' ? packAsciiToField(a.value).toString() : BigInt(a.value).toString(),
        salt: BigInt(a.saltHex).toString()
    })
    const mapProof = (p) => ({
        pathElements: p.pathElements.map(x => BigInt(x).toString()),
        pathIndices: p.pathIndices
    })

    // Age >= (uses birthYear)
    {
        const a = getAttr('birthYear')
        const f = toField(a)
        const p = bundle.attrProofs.birthYear
        const input = {
            valueField: f.valueField,
            salt: f.salt,
            ...mapProof(p),
            root: BigInt(root).toString(),
            minAge: '18',
            nowYear: '2025'
        }
        writeJSON(path.join(outDir, 'input.age_gte.json'), input)
    }

    // Age <= (uses birthYear)
    {
        const a = getAttr('birthYear')
        const f = toField(a)
        const p = bundle.attrProofs.birthYear
        const input = {
            valueField: f.valueField,
            salt: f.salt,
            ...mapProof(p),
            root: BigInt(root).toString(),
            maxAge: '30',
            nowYear: '2025'
        }
        writeJSON(path.join(outDir, 'input.age_lte.json'), input)
    }

    // Attr equals: name
    {
        const a = getAttr('name')
        const f = toField(a)
        const p = bundle.attrProofs.name
        const target = packAsciiToField(a.value).toString()
        const input = {
            valueField: f.valueField,
            salt: f.salt,
            ...mapProof(p),
            root: BigInt(root).toString(),
            target
        }
        writeJSON(path.join(outDir, 'input.attr_name_equals.json'), input)
    }

    // Attr equals: dob
    {
        const a = getAttr('dob')
        const f = toField(a)
        const p = bundle.attrProofs.dob
        const target = packAsciiToField(a.value).toString()
        const input = {
            valueField: f.valueField,
            salt: f.salt,
            ...mapProof(p),
            root: BigInt(root).toString(),
            target
        }
        writeJSON(path.join(outDir, 'input.attr_dob_equals.json'), input)
    }

    // Income >=
    {
        const a = getAttr('income')
        const f = toField(a)
        const p = bundle.attrProofs.income
        const input = {
            valueField: f.valueField,
            salt: f.salt,
            ...mapProof(p),
            root: BigInt(root).toString(),
            minIncome: '500000'
        }
        writeJSON(path.join(outDir, 'input.income_gte.json'), input)
    }

    console.log('Generated circuit input files in .out/*.json')
}

main().catch((e) => { console.error(e); process.exit(1) })
