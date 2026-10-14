import { createStore } from 'solid-js/store';
import { untrack } from 'solid-js';

import { clientsAdd, clientsUpdate } from 'panel/api/generated';
import type { Client } from 'panel/api/model/client';
import { validateIdentifier } from 'panel/helpers/validators';
import { addErrorToast, addSuccessToast } from './toasts';
import intl from 'panel/common/intl';
import { dashboardState, getClients } from './dashboard';

export type ClientFormState = {
    name: string;
    originalName: string;
    ids: string[];
    upstreams: string;
    processingSave: boolean;
    formErrors: Record<string, string | (string | undefined)[]>;
};

const initialState = (): ClientFormState => ({
    name: '',
    originalName: '',
    ids: [''],
    upstreams: '',
    processingSave: false,
    formErrors: {},
});

const [state, setState] = createStore<ClientFormState>(initialState());

export const clientFormState = untrack(() => state);

export const initClientForm = (client?: Partial<Client> | null) => {
    if (!client) {
        setState(initialState());
        return;
    }

    setState({
        ...initialState(),
        name: client.name || '',
        originalName: client.name || '',
        ids: client.ids?.length ? [...client.ids] : [''],
        upstreams: (client.upstreams || []).join('\n'),
    });
};

export const updateClientFormField = <K extends keyof ClientFormState>(
    field: K,
    value: ClientFormState[K],
) => {
    setState(field, value);
    if (field !== 'formErrors' && state.formErrors[field]) {
        setState('formErrors', (errors) => {
            const next = { ...errors };
            delete next[field];
            return next;
        });
    }
};

export const setFormErrors = (errors: ClientFormState['formErrors']) => {
    setState('formErrors', errors);
};

export const clearClientForm = () => setState(initialState());

export const computeExistingClientIds = () =>
    (dashboardState.clients || [])
        .filter((client) => client.name !== state.originalName)
        .flatMap((client) => client.ids || []);

export const buildClientConfig = (
    form: Pick<ClientFormState, 'name' | 'ids' | 'upstreams'>,
): Client => ({
    name: form.name.trim(),
    ids: form.ids.map((id) => id.trim()).filter(Boolean),
    upstreams: form.upstreams
        .split(/\r?\n/)
        .map((upstream) => upstream.trim())
        .filter(Boolean),
});

export const saveClient = async (): Promise<boolean> => {
    const errors: ClientFormState['formErrors'] = {};
    const name = state.name.trim();
    if (!name) {
        errors.name = intl.getMessage('form_error_required');
    } else if (
        dashboardState.clients?.some(
            (client) => client.name === name && client.name !== state.originalName,
        )
    ) {
        errors.name = intl.getMessage('client_name_already_exists');
    }

    const ids = state.ids.map((id) => id.trim()).filter(Boolean);
    const existingIds = computeExistingClientIds();
    const idErrors = state.ids.map((id, index) =>
        id.trim() ? validateIdentifier(id, state.ids, index, existingIds) : undefined,
    );
    if (idErrors.some(Boolean)) errors.ids = idErrors;
    if (!ids.length) errors.ids = [intl.getMessage('form_error_required')];
    if (Object.keys(errors).length) {
        setFormErrors(errors);
        return false;
    }

    const client = buildClientConfig({ name, ids, upstreams: state.upstreams });
    setState('processingSave', true);
    try {
        if (state.originalName) {
            await clientsUpdate({ name: state.originalName, data: client });
        } else {
            await clientsAdd(client);
            addSuccessToast(intl.getMessage('client_added'));
        }
        clearClientForm();
        await getClients();
        return true;
    } catch (error) {
        addErrorToast({ error });
        return false;
    } finally {
        setState('processingSave', false);
    }
};
