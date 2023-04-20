package com.contrast.model;

import java.util.List;
import java.util.Objects;

public class APIKey {

    private String success;
    private List<String> messages;
    private String api_key;

    public APIKey() {
    }

    public APIKey(String success, List<String> messages, String api_key) {
        this.success = success;
        this.messages = messages;
        this.api_key = api_key;
    }

    public String getSuccess() {
        return success;
    }

    public void setSuccess(String success) {
        this.success = success;
    }

    public List<String> getMessages() {
        return messages;
    }

    public void setMessages(List<String> messages) {
        this.messages = messages;
    }

    public String getApi_key() {
        return api_key;
    }

    public void setApi_key(String api_key) {
        this.api_key = api_key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        APIKey apiKey = (APIKey) o;
        return Objects.equals(success, apiKey.success) && Objects.equals(messages, apiKey.messages) && Objects.equals(api_key, apiKey.api_key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(success, messages, api_key);
    }
}
