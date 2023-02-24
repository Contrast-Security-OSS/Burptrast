package com.contrast.mapper;

import com.contrast.Logger;

import java.util.Arrays;

public enum IssueTypeMapper {


    HEADER_INJECTION("header-injection",2097664),
    SESSION_REWRITING("session-rewriting",5244672),
    SESSION_TIMEOUT("session-timeout",134217728),
    CRYPTO_BAD_CIPHERS("crypto-bad-ciphers",134217728),
    CRYPTO_BAD_MAC("crypto-bad-mac",134217728),
    UNVALIDATED_FORWARD("unvalidated-forward",5243136),
    COMMAND_INJECTION("cmd-injection",1048832),
    CONTENT_INJECTION("content-injection",134217728),
    NOSQL_INJECTION("nosql-injection",1049088),
    NOSQL_INJECTION_DYNAMODB("nosql-injection-dynamodb",1049088),
    PATH_TRAVERSAL("path-traversal",1049344),
    REDOS("redos",5246208),
    REFLECTED_XSS("reflected-xss",2097920),
    SSRF("ssrf",3146256),
    SQL_INJECTION("sql-injection",1049088),
    TRUST_BOUNDARY_VIOLATION("trust-boundary-violation",134217728),
    UNSAFE_CODE_EXECUTION("unsafe-code-execution",1052672),
    UNTRUSTED_DESERIALIZATION("untrusted-deserialization",4196608),
    XPATH_INJECTION("xpath-injection",1050112),
    AUTO_COMPLETE_MISSING("autocomplete-missing",5244928),
    CACHE_CONTROLS_MISSING("cache-controls-missing",7340288),
    CSP_MISCONFIGURED("csp-header-insecure",7340288),
    CSP_MISSING("csp-header-missing",7340288),
    INSECURE_AUTH_PROTOCOL("insecure-auth-protocol",7340288),
    PARAMETER_POLLUTION("parameter-pollution",5248000),
    HSTS_HEADER_MISSING("parameter-pollution",16777984),
    X_CONTENT_TYPE_MISCONFIGURED("xcontenttype-header-missing",8389632),
    X_FRAME_OPTIONS_MISCONFIGURED("clickjacking-control-missing",5245344),
    X_POWERED_BY_SET("x-powered-by-header",8389632),
    X_XSS_PROTECTION_DISABLED("xxssprotection-header-disabled",5245360),
    UNKNOWN("UNKNOWN",134217728);


    private final String contrastType;
    private final Integer burpType;

    IssueTypeMapper(String contrastType, Integer burpType) {
        this.contrastType = contrastType;
        this.burpType = burpType;
    }


    public static IssueTypeMapper getIssueType(String contrastType, Logger logger) {
        IssueTypeMapper issueType =  Arrays.stream(IssueTypeMapper.values())
                .filter(issue-> issue.contrastType.equals(contrastType))
                .findFirst()
                .orElse(IssueTypeMapper.UNKNOWN);
        if(IssueTypeMapper.UNKNOWN.equals(issueType)) {
            logger.logError("Unknown vulnerability type : " + contrastType);
        }
        return issueType;
    }

    public Integer getBurpType() {
        return burpType;
    }

    public String getContrastType() {
        return contrastType;
    }
}
