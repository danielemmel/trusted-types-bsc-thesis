class SanitizerLibrary {

    constructor(config) {
        this.config = config
        this.decisionCache = new Map();
    }

    getCallingParty(ignoreSet) {
        // check stacktrace only after "Error at" line and the two callers in the SanitizerLibrary class
        const trace = ((new Error()).stack).split('\n').slice(3)
        for (let s of trace) {
            let a = s.match(/https?:\/\/.*\//)
            if (a && !ignoreSet.has(a[0].slice(0, -1)))
                return (new URL(a[0].slice(0, -1))).origin
        }

    }


    checkHash(input, allowSet, party, trustedType) {
        const hash = CryptoJS.SHA256(input).toString()
        if (allowSet.has(hash)) {
            return input
        } else {
            console.warn(`[Processing ${trustedType} for ${party} in mode hashes]\n hash ${hash} from input ${input} did not match any hash in the allowlist ${JSON.stringify([...allowSet])}`)
            return null
        }
    }

    isJSON(input) {
        try {
            JSON.parse(input);
            return true;
        } catch (e) {
        }
        try {
            JSON.parse(input.slice(1, -1));
            return true;
        } catch (e) {
        }
        return false;
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

    checkScripts(input, hashSet, prefixSet, trustedType, party, strict, regexSet = new Map()) {
        // no hashes and no hosts are allowed, i.e. no scripts should be used
        if (hashSet.size === 0 && prefixSet.size === 0 && regexSet.size === 0)
            return DOMPurify.sanitize(input);

        // dummy policy to allow feeding input to DOMParser parsing function
        const dummy = trustedTypes.createPolicy('dummy', {
            createHTML: (input) => {
                return input
            }
        });

        let parser = new DOMParser()
        let res = parser.parseFromString(dummy.createHTML(input), 'text/html')


        let elems = res.getElementsByTagName("*");
        elemloop:
            for (let i = elems.length - 1; i >= 0; i--) {
                let elem = elems[i];
                for (let j = elem.attributes.length - 1; j >= 0; j--) {
                    let attr = elem.attributes[j];
                    // check event handlers of HTMLelements
                    if (attr.nodeName.startsWith('on') && attr.nodeValue && !hashSet.has(CryptoJS.SHA256(attr.nodeValue).toString()) &&
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
                    if (elem.innerText === '' || hashSet.has(CryptoJS.SHA256(elem.innerText).toString()) ||
                        this.checkAgainstRegexes(elem.innerText, regexSet, party, trustedType) !== null)
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


    sanitizeHTML(input, subConfig, party, trustedType) {
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
                        return this.checkScripts(input, subConfig['scripts']['hashes'], subConfig['scripts']['prefixes'], trustedType, party, strict, subConfig['scripts']['regexes'])
                    else
                        return this.checkScripts(input, subConfig['scripts']['hashes'], subConfig['scripts']['prefixes'], trustedType, party, strict)

                default:
                    console.error(`Unknown mode ${mode} for type ${trustedType}`)
                    return null
            }
        }
        return null
    }

    sanitizeScript(input, subConfig, party, trustedType) {
        // if input is json parsable, it's not dangerous
        if (this.isJSON(input))
            return input;

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


    sanitizeScriptURL(input, subConfig, party, trustedType, blob = false) {
        let url;
        try {
            url = new URL(input, location.origin)
        } catch (e) {
            console.warn(`[Processing ${trustedType} for ${party}]\n URL ${input} was not parseable`)
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
                        return this.sanitizeScriptURL(input.slice(5), subConfig, party, trustedType, true);
                    break;

                default:
                    console.error(`Unknown mode ${mode} for type ${trustedType}`)
                    return null
            }
        }
        return null
    }


    sanitizeInput(input, trustedType) {
        // Always accept empty inputs
        if (!input)
            return input
        const party = this.getCallingParty(this.config['ignoreList'])
        const subConfig = this.config[party][trustedType]

        if (!subConfig) {
            console.warn(`No subconfig found in config for party ${party}`)
            return null
        }

        // config says that any input of this type should be allowed
        if (subConfig['allow-any'])
            return input;
        delete subConfig['allow-any'];

        let hash = CryptoJS.SHA256(input + party + trustedType).toString();
        // return previous decision for this combination from cache if existant
        if (this.decisionCache.has(hash))
            if (trustedType !== 'TrustedHTML' || subConfig['strict'])
                return this.decisionCache.get(hash) ? input : null;
            else
                return this.decisionCache.get(hash) ? input : this.sanitizeHTML(input, subConfig, party, trustedType);
        let res;
        switch (trustedType) {
            case 'TrustedHTML':
                res = this.sanitizeHTML(input, subConfig, party, trustedType);
                // save decision for future
                this.decisionCache.set(hash, res === input);
                return res;
            case 'TrustedScript':
                res = this.sanitizeScript(input, subConfig, party, trustedType);
                this.decisionCache.set(hash, res === input);
                return res;
            case 'TrustedScriptURL':
                res = this.sanitizeScriptURL(input, subConfig, party, trustedType);
                this.decisionCache.set(hash, res === input);
                return res;
            default:
                console.error(`Unknown Trusted Type value: ${trustedType}`)
                return null
        }
    }
}