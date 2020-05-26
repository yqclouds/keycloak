package com.yqboots.security.web.access;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.util.ArrayList;
import java.util.List;

/**
 * Method security configuration.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@EnableGlobalMethodSecurity(prePostEnabled = true, jsr250Enabled = false, securedEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {
    @Autowired
    private RoleHierarchy roleHierarchy;

    @Autowired
    private PermissionEvaluator permissionEvaluator;

    /**
     * {@inheritDoc}
     */
    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler bean = new DefaultMethodSecurityExpressionHandler();
        bean.setDefaultRolePrefix(StringUtils.EMPTY);
        bean.setPermissionEvaluator(permissionEvaluator);
        bean.setRoleHierarchy(roleHierarchy);

        return bean;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<>();

        ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
        expressionAdvice.setExpressionHandler(getExpressionHandler());
        decisionVoters.add(new PreInvocationAuthorizationAdviceVoter(expressionAdvice));

        // decisionVoters.add(new RoleVoter());
        decisionVoters.add(roleVoter());
        decisionVoters.add(new Jsr250Voter());
        decisionVoters.add(new AuthenticatedVoter());
        decisionVoters.add(roleHierarchyVoter());
        return new AffirmativeBased(decisionVoters);
    }

    private RoleVoter roleVoter() {
        RoleVoter bean = new RoleVoter();
        bean.setRolePrefix(StringUtils.EMPTY);
        return bean;
    }

    private RoleVoter roleHierarchyVoter() {
        RoleVoter bean = new RoleHierarchyVoter(roleHierarchy);
        bean.setRolePrefix(StringUtils.EMPTY);
        return bean;
    }
}
