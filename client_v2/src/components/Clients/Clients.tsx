import { createSignal, Show, onMount } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import cn from 'clsx';

import intl from 'panel/common/intl';
import { ConfirmDialog } from 'panel/common/ui/ConfirmDialog';
import { PlusButton } from 'panel/common/ui/PlusButton';
import { dashboardState, getClients } from 'panel/stores/dashboard';
import { statsState, getStats } from 'panel/stores/stats';
import { clientsState, deleteClient } from 'panel/stores/clients';
import { initClientForm } from 'panel/stores/clientForm';
import type { Client } from 'panel/api/model/client';
import { RoutePath, Paths, linkPathBuilder } from 'panel/components/Routes/Paths';
import theme from 'panel/lib/theme';

import { PersistentClientsTable } from './blocks/PersistentClientsTable';
import s from './Clients.module.pcss';

export const Clients = () => {
    const navigate = useNavigate();
    const [clientNameToDelete, setClientNameToDelete] = createSignal('');

    onMount(() => {
        getClients();
        getStats();
    });

    const add = () => {
        initClientForm();
        navigate(Paths.ClientsAdd);
    };
    const edit = (client: Client) => {
        initClientForm(client);
        navigate(
            linkPathBuilder(RoutePath.ClientsEdit, {
                clientName: encodeURIComponent(client.name || ''),
            }),
        );
    };

    return (
        <div class={theme.layout.container}>
            <div class={theme.layout.containerIn}>
                <h1
                    class={cn(theme.layout.title, theme.title.h4, theme.title.h3_tablet)}
                    data-testid="clients-title"
                >
                    {intl.getMessage('clients')}
                </h1>
                <div class={s.desc}>{intl.getMessage('clients_desc')}</div>
                <PlusButton onClick={add} testId="clients-add-button">
                    {intl.getMessage('clients_add')}
                </PlusButton>
                <Show when={dashboardState.clients?.length}>
                    <div class={s.tableSection}>
                        <PersistentClientsTable
                            clients={dashboardState.clients || []}
                            normalizedTopClients={statsState.normalizedTopClients}
                            loading={!dashboardState.clientsInitialized}
                            onEdit={edit}
                            onDelete={setClientNameToDelete}
                            deleteDisabled={clientsState.processingDeleting}
                        />
                    </div>
                </Show>
                <Show when={clientNameToDelete()}>
                    <ConfirmDialog
                        onClose={() => setClientNameToDelete('')}
                        onConfirm={() => {
                            deleteClient(clientNameToDelete());
                            setClientNameToDelete('');
                        }}
                        submitDisabled={clientsState.processingDeleting}
                        buttonText={intl.getMessage('yes_remove')}
                        cancelText={intl.getMessage('cancel')}
                        title={intl.getMessage('clients_remove_title')}
                        text={intl.getMessage('clients_remove_desc', {
                            value: clientNameToDelete(),
                        })}
                        buttonVariant="danger"
                    />
                </Show>
            </div>
        </div>
    );
};
