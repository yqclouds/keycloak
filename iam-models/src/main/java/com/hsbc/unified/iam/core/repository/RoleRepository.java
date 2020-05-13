package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<Role, String>, JpaSpecificationExecutor<Role> {
    @Query(name = "getClientRoles", value = "select role from Role role where role.client.id = :client order by role.name")
    List<Role> getClientRoles(String client);

    @Query(name = "getClientRoleIds", value = "select role.id from Role role where role.client.id = :client")
    List<String> getClientRoleIds(String client);

    @Query(name = "getClientRoleByName", value = "select role from Role role where role.name = :name and role.client = :client")
    List<Role> getClientRoleByName(String name, String client);

    @Query(name = "getClientRoleIdByName", value = "select role.id from Role role where role.name = :name and role.client.id = :client")
    List<String> getClientRoleIdByName(String name, String client);

    @Query(name = "searchForClientRoles", value = "select role from Role role where role.client.id = :client and ( lower(role.name) like :search or lower(role.description) like :search ) order by role.name")
    List<Role> searchForClientRoles(String client, String search);

    @Query(name = "getRealmRoles", value = "select role from Role role where role.clientRole = false and role.realm.id = :realm order by role.name")
    List<Role> getRealmRoles(String realm);

    @Query(name = "getRealmRoleIds", value = "select role.id from Role role where role.clientRole = false and role.realm.id = :realm")
    List<String> getRealmRoleIds(String realm);

    @Query(name = "getRealmRoleByName", value = "select role from Role role where role.clientRole = false and role.name = :name and role.realm = :realm")
    List<Role> getRealmRoleByName(String realm);

    @Query(name = "getRealmRoleIdByName", value = "select role.id from Role role where role.clientRole = false and role.name = :name and role.realm.id = :realm")
    List<String> getRealmRoleIdByName(String name, String realm);

    @Query(name = "searchForRealmRoles", value = "select role from Role role where role.clientRole = false and role.realm.id = :realm and ( lower(role.name) like :search or lower(role.description) like :search ) order by role.name")
    List<Role> searchForRealmRoles(String realm, String search);

    @Query(nativeQuery = true, value = "delete from COMPOSITE_ROLE where CHILD_ROLE = :role")
    void deleteCompositeRoles(Role role);
}
