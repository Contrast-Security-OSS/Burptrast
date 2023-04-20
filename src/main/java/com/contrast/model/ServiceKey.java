package com.contrast.model;

import java.util.List;
import java.util.Objects;

public class ServiceKey {

    private String success;
    private List<String> messages;
    private String service_key;
    private String user_uid;


    public ServiceKey() {
    }

    public ServiceKey(String success, List<String> messages, String service_key, String user_uid) {
        this.success = success;
        this.messages = messages;
        this.service_key = service_key;
        this.user_uid = user_uid;
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

    public String getService_key() {
        return service_key;
    }

    public void setService_key(String service_key) {
        this.service_key = service_key;
    }

    public String getUser_uid() {
        return user_uid;
    }

    public void setUser_uid(String user_uid) {
        this.user_uid = user_uid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServiceKey that = (ServiceKey) o;
        return Objects.equals(success, that.success) && Objects.equals(messages, that.messages) && Objects.equals(service_key, that.service_key) && Objects.equals(user_uid, that.user_uid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(success, messages, service_key, user_uid);
    }
}
