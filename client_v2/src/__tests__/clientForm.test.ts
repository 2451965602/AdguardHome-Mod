import { beforeEach, describe, expect, it } from 'vitest';

import {
    buildClientConfig,
    clientFormState,
    initClientForm,
} from 'panel/stores/clientForm';

describe('client form upstreams', () => {
    beforeEach(() => initClientForm());

    it('serializes multiline upstreams into a trimmed string array', () => {
        expect(
            buildClientConfig({
                name: '  Home  ',
                ids: ['192.168.1.10'],
                upstreams: '  1.1.1.1  \n\n  tls://dns.example  \n',
            }),
        ).toEqual({
            name: 'Home',
            ids: ['192.168.1.10'],
            upstreams: ['1.1.1.1', 'tls://dns.example'],
        });
    });

    it('restores the upstream array as multiline form text when editing', () => {
        initClientForm({
            name: 'Home',
            ids: ['192.168.1.10'],
            upstreams: ['1.1.1.1', 'tls://dns.example'],
        });

        expect(clientFormState.upstreams).toBe('1.1.1.1\ntls://dns.example');
    });
});
