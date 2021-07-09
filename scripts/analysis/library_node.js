/*
This is a recreation of the client-side SanitizerLibrary only used for easier evaluation of the functionality of the created configs against the database.
*/

const createDOMPurify = require('dompurify');
const {JSDOM} = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const crypto = require('crypto');
const esprima = require('esprima');

function atob(str) {
    return Buffer.from(str).toString('base64');
}

function btoa(str) {
    return Buffer.from(str, 'base64').toString('ascii');
}

class SanitizerLibrary {

    constructor(config) {
        this.config = config
    }

    checkHash(input, allowSet, party, trustedType) {
        const hash = ((crypto.createHash('sha256')).update(input)).digest('hex')
        if (allowSet.has(hash)) {
            return input
        } else {
            // console.warn(`[Processing ${trustedType} for ${party} in mode hashes]\n hash ${hash} from input ${input} did not match any hash in the allowlist ${JSON.stringify(allowSet)}`)
            return null
        }
    }

    checkPossibleETLDs(url, allowSet, party, trustedType) {
        let host = url.hostname
        let parts = host.split('.')
        let domain = parts.pop()
        do {
            // attempt building eTLDs until a match is found
            domain = parts.pop() + '.' + domain
            if (allowSet.has(domain))
                return url
        } while (parts.length > 0);
        return null
    }

    checkAgainstRegexes(input, allowSet, party, trustedType) {
        // remove any block comments
        input = input.replace(new RegExp('/\\*.*\\*/', 'gs'), '');
        // remove any one-line comments but not URLs
        for (let token of esprima.tokenize(input, {comment: true, tolerant: true})) {
            if (token.type === 'LineComment')
                input = input.replace(`//${token.value}`, '');
        }
        // remove any whitespace-like characters
        input = input.replace(new RegExp('\\s', 'g'), '');
        // check against set of regexes
        for (let regexStr of allowSet) {
            let regex = new RegExp(regexStr);
            if (regex.test(input))
                return input;
        }
        return null;
    }

    checkDataHashes(input, allowSet, trustedType, party) {
        const seperatorIndex = input.search(',') + 1
        // get actual data content
        let data = input.slice(seperatorIndex)
        const prefix = input.slice(5, seperatorIndex)
        // decode data for checking
        if (prefix.includes('base64'))
            data = atob(data)

        // check if hash is in list of allowed values
        if (allowSet.has(CryptoJS.SHA256(data).toString()))
            return input
        return null
    }

    checkScripts(input, hashSet, prefixSet, trustedType, party, strict, regexSet = new Map(), origin) {
        // no hashes and no hosts are allowed, i.e. no scripts should be used
        if (hashSet.size === 0 && prefixSet.size === 0 && regexSet.size === 0)
            return strict ? null : DOMPurify.sanitize(input)


        let res = (new JSDOM(input)).window.document;

        let elems = res.getElementsByTagName("*");
        elemloop:
            for (let i = elems.length - 1; i >= 0; i--) {
                let elem = elems[i];
                for (let j = elem.attributes.length - 1; j >= 0; j--) {
                    let attr = elem.attributes[j];
                    // check event handlers of HTMLelements
                    if (attr.nodeName.startsWith('on') && attr.nodeValue && !hashSet.has(((crypto.createHash('sha256')).update(attr.nodeValue)).digest('hex')) &&
                        this.checkAgainstRegexes(attr.nodeValue, regexSet, party, trustedType) === null) {
                        if (strict)
                            return null
                        else
                            elem.removeAttribute(attr.nodeName)
                    }
                }
                if (elem.tagName.toLowerCase() === 'script') {
                    // check inline scripts in parsed HTML against hashes
                    // and check external scripts' src against hostlist
                    if (elem.textContent === '' || hashSet.has(((crypto.createHash('sha256')).update(elem.textContent)).digest('hex')) ||
                        this.checkAgainstRegexes(elem.textContent, regexSet, party, trustedType) !== null)
                        continue;
                    for (let prefix of prefixSet) {
                        if (elem.src.startsWith(prefix))
                            continue elemloop;
                    }

                    // script did not match requirements
                    if (strict)
                        return null
                    else
                        elem.remove()
                }

                // remove scripts present in iframes with data URLs
                if (elem.tagName.toLowerCase() === 'iframe' && elem.src && elem.src.startsWith('data:')) {
                    window.src = elem.src
                    const seperatorIndex = src.search(',') + 1
                    let data = src.slice(seperatorIndex)
                    const prefix = src.slice(0, seperatorIndex)
                    // decode data for sanitizing
                    let encoded = prefix.includes('base64')
                    if (encoded)
                        data = atob(data)

                    // let DOMPurify remove all JS
                    elem.src = prefix + (encoded ? btoa(DOMPurify.sanitize(data)) : DOMPurify.sanitize(data))
                }

            }
        return res.documentElement.outerHTML;
    }


    sanitizeHTML(input, subConfig, party, trustedType, origin) {
        if (subConfig['allow-any'])
            return input;
        delete subConfig['allow-any'];

        let res;
        for (let mode of Object.keys(subConfig)) {
            switch (mode) {
                // check if input hash matches known hash
                case 'hashes':
                    res = this.checkHash(input, subConfig['hashes'], party, trustedType)
                    if (res !== null)
                        return input;
                    break;

                case 'scripts':
                    // parse script tags / event handlers and remove those that are not allowed
                    let strict = subConfig['strict']
                    // strict => don't remove violating JS, but completely reject input instead
                    if (subConfig['scripts'].hasOwnProperty("regexes"))
                        return this.checkScripts(input, subConfig['scripts']['hashes'], subConfig['scripts']['prefixes'], trustedType, party, strict, subConfig['scripts']['regexes'], origin)
                    else
                        return this.checkScripts(input, subConfig['scripts']['hashes'], subConfig['scripts']['prefixes'], trustedType, party, strict, origin)

                default:
                    console.error(`Unknown mode ${mode} for type ${trustedType}`)
                    return null
            }
        }
        return null
    }

    sanitizeScript(input, subConfig, party, trustedType) {
        if (subConfig['allow-any'])
            return input;
        delete subConfig['allow-any'];
        // if input is json parsable, it's not dangerous
        try {
            JSON.parse(input);
            return input;
        } catch (e) {
        }
        try {
            JSON.parse(input.slice(1, -1));
            return input;
        } catch (e) {
        }

        let res;
        for (let mode of Object.keys(subConfig)) {
            switch (mode) {
                // check if input hash matches known hash
                case 'hashes':
                    res = this.checkHash(input, subConfig['hashes'], party, trustedType)
                    if (res !== null)
                        return input;
                    break;

                case 'regexes':
                    // check whether input matches any of the regexes allowed
                    res = this.checkAgainstRegexes(input, subConfig['regexes'], party, trustedType)
                    if (res !== null)
                        return input;
                    break;


                default:
                    console.error(`Unknown mode ${mode} for type ${trustedType}`)
                    return null
            }
        }
        return null
    }


    sanitizeScriptURL(input, subConfig, party, trustedType, origin, blob = false) {
        if (subConfig['allow-any'])
            return input;
        delete subConfig['allow-any'];

        let url;
        try {
            url = new URL(input, origin)
        } catch (e) {
            console.warn(`[Processing ${trustedType} for ${party}]\n URL ${input} was not parseable`);
            return null
        }
        for (let mode of Object.keys(subConfig)) {
            let res;
            switch (mode) {
                // check if full URL hash matches known hash
                case 'hashes':
                    res = this.checkHash(input, subConfig['hashes'], party, trustedType)
                    if (res !== null)
                        return blob ? `blob:${input}` : input;
                    break;

                case 'origins':
                    // check whether origin of URL is in allowed origins
                    if (subConfig['origins'].has(url.origin))
                        return blob ? `blob:${input}` : input;
                    break;

                case 'hosts':
                    // check whether hostname of URL is in allowed hosts
                    if (subConfig['hosts'].has(url.hostname))
                        return blob ? `blob:${input}` : input;
                    break;
                case 'prefixes':
                    // check if URL given begin with any allowed prefix
                    for (let prefix of subConfig['prefixes']) {
                        if (input.startsWith(prefix))
                            return blob ? `blob:${input}` : input;
                    }
                    break;
                case 'eTLDs':
                    // check whether the eTLD+1 is in the list of allowed values
                    res = this.checkPossibleETLDs(url, subConfig['eTLDs'], party, trustedType)
                    if (res !== null)
                        return blob ? `blob:${input}` : input;
                    break;
                case 'dataHashes':
                    if (input.startsWith('data:')) {
                        // check data URL against allowed hashes
                        res = this.checkDataHashes(input, subConfig['dataHashes'], party, trustedType)
                        if (res !== null)
                            return input;
                    } else if (input.startsWith('blob:'))
                        // blob URLs are always followed by a http URL
                        // => check that http URL like normal
                        return this.sanitizeScriptURL(input.slice(5), subConfig, party, trustedType, origin, true);
                    break;

                default:
                    console.error(`Unknown mode ${mode} for type ${trustedType}`)
                    return null
            }
        }
        return null
    }
}

module.exports = SanitizerLibrary
