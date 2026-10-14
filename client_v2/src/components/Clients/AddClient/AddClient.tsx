import { createEffect, createSignal, onMount, Show } from 'solid-js';
import { useNavigate, useParams } from '@solidjs/router';
import cn from 'clsx';

import intl from 'panel/common/intl';
import { Button } from 'panel/common/ui/Button';
import { Input } from 'panel/common/controls/Input';
import { Textarea } from 'panel/common/controls/Textarea';
import { PageLoader } from 'panel/common/ui/Loader';
import { dashboardState, getClients } from 'panel/stores/dashboard';
import {
    clearClientForm,
    clientFormState,
    initClientForm,
    saveClient,
    setFormErrors,
    updateClientFormField,
} from 'panel/stores/clientForm';
import type { Client } from 'panel/api/model/client';
import { Paths } from 'panel/components/Routes/Paths';
import theme from 'panel/lib/theme';

import { Identifiers } from './blocks/Identifiers/Identifiers';
import s from './AddClient.module.pcss';

export const AddClient = () => {
    const navigate = useNavigate();
    const params = useParams<{ clientName?: string }>();
    const [nameError, setNameError] = createSignal<string>();

    onMount(() => getClients());

    createEffect(() => {
        const name = params.clientName;
        const clients = dashboardState.clients || [];
        if (!name || !clients.length || clientFormState.originalName) return;

        const client = clients.find((item: Client) => item.name === decodeURIComponent(name));
        if (!client) {
            navigate(Paths.Clients, { replace: true });
            return;
        }
        initClientForm(client);
    });

    createEffect(() => {
        const error = clientFormState.formErrors.name;
        setNameError(typeof error === 'string' ? error : undefined);
    });

    const handleSave = async () => {
        const result = await saveClient();
        if (result) navigate(Paths.Clients);
    };

    const handleCancel = () => {
        clearClientForm();
        navigate(Paths.Clients);
    };

    return (
        <div class={cn(theme.layout.container, s.containerOverride)} data-testid="client-form">
            <div class={theme.layout.containerIn}>
                <h1 class={cn(theme.layout.title, theme.title.h4, theme.title.h3_tablet)}>
                    {clientFormState.originalName
                        ? intl.getMessage('clients_edit')
                        : intl.getMessage('clients_add')}
                </h1>
                <Show when={clientFormState.processingSave}>
                    <PageLoader />
                </Show>
                <Show when={!clientFormState.processingSave}>
                    <div class={s.fieldGroupInput}>
                        <Input
                            id="client-name"
                            data-testid="client-form-name"
                            value={clientFormState.name}
                            onInput={(event) =>
                                updateClientFormField('name', event.currentTarget.value)
                            }
                            placeholder={intl.getMessage('clients_add_placeholder')}
                            label={intl.getMessage('clients_add_name')}
                            size="large"
                            error={!!nameError()}
                            errorMessage={nameError()}
                        />
                    </div>
                    <div class={s.section}>
                        <Identifiers />
                    </div>
                    <div class={s.section}>
                        <Textarea
                            id="client-upstreams"
                            value={clientFormState.upstreams}
                            onInput={(event) => {
                                updateClientFormField('upstreams', event.currentTarget.value);
                                setFormErrors({ ...clientFormState.formErrors, upstreams: '' });
                            }}
                            placeholder={intl.getMessage('upstream_dns_placeholder')}
                            label={intl.getMessage('clients_upstreams_desc')}
                            rows={4}
                            highlightComments
                        />
                    </div>
                    <div class={s.actions}>
                        <Button
                            variant="primary"
                            size="small"
                            onClick={handleSave}
                            data-testid="client-form-save"
                            class={s.actionButton}
                        >
                            {intl.getMessage('save_btn')}
                        </Button>
                        <Button
                            variant="secondary"
                            size="small"
                            onClick={handleCancel}
                            data-testid="client-form-cancel"
                            class={s.actionButton}
                        >
                            {intl.getMessage('cancel_btn')}
                        </Button>
                    </div>
                </Show>
            </div>
        </div>
    );
};
