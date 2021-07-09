const {Client} = require('pg');
const fs = require('fs');
const createDOMPurify = require('dompurify');
const {JSDOM} = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const SanitizerLibrary = require('./library_node');

function performArraySubstitution(obj) {
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            if (Array.isArray(obj[key]))
                obj[key] = new Set(obj[key])
            else
                performArraySubstitution(obj[key])
        }
    }
}

function getClient() {
    let credentials = fs.readFileSync('/data/credentials.json')
    credentials = JSON.parse(credentials)
    return new Client({
        user: credentials.db_user,
        host: credentials.db_host,
        database: credentials.db_name,
        password: credentials.db_pass,
        port: credentials.db_port,
    });
}

function getConfig(hostname) {
    let filename = `/data/configs/${hostname}_config.json`
    let content = fs.readFileSync(filename)
    return JSON.parse(content)
}


function countValidInputs(inputs, lib, origin) {
    let counter = 0;
    for (let input of inputs) {
        let after;
        let subConfig = lib.config[input.party];
        if (!subConfig || !subConfig[input.type])
            continue;
        switch (input.type) {
            case 'TrustedHTML':
                after = lib.sanitizeHTML(input.content, subConfig[input.type], input.party, input.type, origin);
                if (after === input.content || after === DOMPurify.sanitize(input.content) || (new JSDOM(after)).window.document.documentElement.outerHTML === (new JSDOM(input.content)).window.document.documentElement.outerHTML)
                    counter++;
                break;
            case 'TrustedScript':
                after = lib.sanitizeScript(input.content, subConfig[input.type], input.party, input.type);
                if (after === input.content)
                    counter++;
                break;
            case 'TrustedScriptURL':
                after = lib.sanitizeScriptURL(input.content, subConfig[input.type], input.party, input.type, origin);
                if (after === input.content)
                    counter++;
                break;
            default:
                console.warn(`Unknown Trusted Type ${input.type} found, skipping`)
        }
    }
    return counter;
}

async function getInputsForOrigin(client, origin) {
    let res = await client.query('SELECT DISTINCT input_hash, trusted_type, party_origin FROM tt_data WHERE origin=$1;', [origin]);
    let inputs = [];
    for (let row of res.rows) {
        let type = row.trusted_type
        let hash = row.input_hash
        let filename = `/data/inputs/${hash.slice(0, 2)}/${hash}.txt`
        // these exhibit strange behavior, so ignore them for now
        if(row.party_origin !== null)
            inputs.push({
                'content': fs.readFileSync(filename).toString(),
                'type': type,
                'party': row.party_origin
            });
    }
    return inputs;
}

async function main() {
    const client = getClient();
    await client.connect();

    let validCounter = 0, inputCounter = 0;
    let res = await client.query("SELECT DISTINCT origin FROM tt_data;")
    for (let entry of res.rows) {
        let origin = entry.origin
        let inputs = await getInputsForOrigin(client, origin);
        let config;
        let hostname;
        try {
            if(origin !== 'null')
                hostname = (new URL(origin)).hostname
            else
                hostname = 'null';
            config = getConfig(hostname);
        } catch (e) {
            console.error(`No config found for origin ${origin}, skipping this origin`)
            continue;
        }
        performArraySubstitution(config);
        let library = new SanitizerLibrary(config);
        let validCount = countValidInputs(inputs, library, origin);
        validCounter += validCount;
        inputCounter += inputs.length;
        console.log(`Non-changed inputs for origin ${origin} : ${validCount}/${inputs.length}`);
    }

    console.log(`\nTotal of non-changed inputs: ${validCounter}/${inputCounter}`);
    if (!fs.existsSync('/data/scripts/results.txt'))
        fs.writeFileSync('/data/scripts/results.txt', `${validCounter}/${inputCounter}\n`);
    else
        fs.appendFileSync('/data/scripts/results.txt', `${validCounter}/${inputCounter}\n`);
    await client.end();
}

main();
