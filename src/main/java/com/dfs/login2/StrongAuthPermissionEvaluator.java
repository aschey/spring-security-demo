package com.dfs.login2;

import java.io.Serializable;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

public class StrongAuthPermissionEvaluator implements PermissionEvaluator {
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        var creds = (Creds)targetDomainObject;
        // Call strong auth API
        if (creds.user.equals("bob")) {
            return true;
        }
        throw new AccessDeniedException("Fraud risk");
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
            Object permission) {
        return false;
    }
}
