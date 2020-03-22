package org.keycloak.exportimport.util;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class ExportOptions {

    private boolean usersIncluded = true;
    private boolean clientsIncluded = true;
    private boolean groupsAndRolesIncluded = true;
    private boolean onlyServiceAccountsIncluded = false;

    public ExportOptions() {
    }

    public ExportOptions(boolean users, boolean clients, boolean groupsAndRoles, boolean onlyServiceAccounts) {
        usersIncluded = users;
        clientsIncluded = clients;
        groupsAndRolesIncluded = groupsAndRoles;
        onlyServiceAccountsIncluded = onlyServiceAccounts;
    }

    public boolean isUsersIncluded() {
        return usersIncluded;
    }

    public void setUsersIncluded(boolean value) {
        usersIncluded = value;
    }

    public boolean isClientsIncluded() {
        return clientsIncluded;
    }

    public void setClientsIncluded(boolean value) {
        clientsIncluded = value;
    }

    public boolean isGroupsAndRolesIncluded() {
        return groupsAndRolesIncluded;
    }

    public void setGroupsAndRolesIncluded(boolean value) {
        groupsAndRolesIncluded = value;
    }

    public boolean isOnlyServiceAccountsIncluded() {
        return onlyServiceAccountsIncluded;
    }

    public void setOnlyServiceAccountsIncluded(boolean value) {
        onlyServiceAccountsIncluded = value;
    }
}
