package com.hsbc.unified.iam.core.repository;

import com.hsbc.unified.iam.core.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GroupRepository extends JpaRepository<Group, String>, JpaSpecificationExecutor<Group> {
    @Query(name = "getGroupIdsByParent", value = "select u.id from Group u where u.parentId = :parent")
    List<String> getGroupIdsByParent(String parent);

    @Query(name = "getGroupIdsByNameContaining", value = "select u.id from Group u where u.realm.id = :realm and u.name like concat('%',:search,'%') order by u.name ASC")
    List<String> getGroupIdsByNameContaining(String realm, String search);

    @Query(name = "getTopLevelGroupIds", value = "select u.id from Group u where u.parentId = :parent and u.realm.id = :realm order by u.name ASC")
    List<String> getTopLevelGroupIds(String parent, String realm);

    @Query(name = "getGroupCount", value = "select count(u) from Group u where u.realm.id = :realm")
    Long getGroupCount(String realm);

    @Query(name = "getTopLevelGroupCount", value = "select count(u) from Group u where u.realm.id = :realm and u.parentId = :parent")
    Long getTopLevelGroupCount(String realm, String parent);
}
