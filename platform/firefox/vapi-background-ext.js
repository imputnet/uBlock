/*******************************************************************************

    uBlock Origin - a comprehensive, efficient content blocker
    Copyright (C) 2017-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

    Home: https://github.com/gorhill/uBlock
*/

import { NetWithDNS } from './vapi-background-dns.js';

/******************************************************************************/

const dnsAPI = browser.dns || {
    resolve() {
        return Promise.resolve();
    }
};

const skipDNS = proxyInfo =>
    proxyInfo && (proxyInfo.proxyDNS || proxyInfo.type?.charCodeAt(0) === 0x68 /* h */);

/******************************************************************************/

// Related issues:
// - https://github.com/gorhill/uBlock/issues/1327
// - https://github.com/uBlockOrigin/uBlock-issues/issues/128
// - https://bugzilla.mozilla.org/show_bug.cgi?id=1503721

// Extend base class to normalize as per platform.

vAPI.Net = class extends NetWithDNS(
    vAPI.Net,
    hn => dnsAPI.resolve(hn, [ 'canonical_name' ]),
    details => skipDNS(details.proxyInfo)
) {
    normalizeDetails(details) {
        // https://github.com/uBlockOrigin/uBlock-issues/issues/3379
        if ( skipDNS(details.proxyInfo) && details.ip === '0.0.0.0' ) {
            details.ip = null;
        }
        const type = details.type;
        if ( type === 'imageset' ) {
            details.type = 'image';
            return;
        }
        if ( type !== 'object' ) { return; }
        // Try to extract type from response headers if present.
        if ( details.responseHeaders === undefined ) { return; }
        const ctype = this.headerValue(details.responseHeaders, 'content-type');
        // https://github.com/uBlockOrigin/uBlock-issues/issues/345
        //   Re-categorize an embedded object as a `sub_frame` if its
        //   content type is that of a HTML document.
        if ( ctype === 'text/html' ) {
            details.type = 'sub_frame';
        }
    }

    denormalizeTypes(types) {
        if ( types.length === 0 ) {
            return Array.from(this.validTypes);
        }
        const out = new Set();
        for ( const type of types ) {
            if ( this.validTypes.has(type) ) {
                out.add(type);
            }
            if ( type === 'image' && this.validTypes.has('imageset') ) {
                out.add('imageset');
            }
            if ( type === 'sub_frame' ) {
                out.add('object');
            }
        }
        return Array.from(out);
    }
};

/******************************************************************************/

vAPI.scriptletsInjector = (( ) => {
    const parts = [
        '(',
        function(details) {
            if ( self.uBO_scriptletsInjected !== undefined ) { return; }
            const doc = document;
            const { location } = doc;
            if ( location === null ) { return; }
            const { hostname } = location;
            if ( hostname !== '' && details.hostname !== hostname ) { return; }
            // Use a page world sentinel to verify that execution was
            // successful
            const { sentinel } = details;
            let script;
            try {
                const code = [
                    `self['${sentinel}'] = true;`,
                    details.scriptlets,
                ].join('\n');
                script = doc.createElement('script');
                script.appendChild(doc.createTextNode(code));
                (doc.head || doc.documentElement).appendChild(script);
            } catch {
            }
            if ( script ) {
                script.remove();
                script.textContent = '';
                script = undefined;
            }
            if ( self.wrappedJSObject[sentinel] ) {
                delete self.wrappedJSObject[sentinel];
                self.uBO_scriptletsInjected = details.filters;
                return 0;
            }
            // https://github.com/uBlockOrigin/uBlock-issues/issues/235
            //   Fall back to blob injection if execution through direct
            //   injection failed
            let url;
            try {
                const blob = new self.Blob(
                    [ details.scriptlets ],
                    { type: 'text/javascript; charset=utf-8' }
                );
                url = self.URL.createObjectURL(blob);
                script = doc.createElement('script');
                script.async = false;
                script.src = url;
                (doc.head || doc.documentElement || doc).append(script);
                self.uBO_scriptletsInjected = details.filters;
            } catch {
            }
            if ( url ) {
                if ( script ) { script.remove(); }
                self.URL.revokeObjectURL(url);
            }
            return 0;
        }.toString(),
        ')(',
            'json-slot',
        ');',
    ];
    const jsonSlot = parts.indexOf('json-slot');
    return (hostname, details) => {
        parts[jsonSlot] = JSON.stringify({
            hostname,
            scriptlets: details.mainWorld,
            filters: details.filters,
            sentinel: vAPI.generateSecret(3),
        });
        return parts.join('');
    };
})();

/******************************************************************************/
