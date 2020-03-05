package com.yousheng.app2.casclient2.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import javax.persistence.*;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.*;

/**
 * @author:lq
 * @date: 2020/3/5
 * @time: 16:11
 */
@Entity
@Table(name = "user_account", schema = "changlebase")
public class UserAccount implements UserDetails,Serializable {
    @Id
    @Column(name = "GUID")
    private String guid;

    @Basic
    @Column(name = "PWD")
    private String pwd;

    @Basic
    @Column(name = "SEQNO")
    private String seqno;

    @Basic
    @Column(name = "CARDID")
    private String cardid;

    @Basic
    @Column(name = "NAME")
    private String name;

    @Basic
    @Column(name = "TEL")
    private String tel;

    @Basic
    @Column(name = "OPERDATE")
    private String operdate;

    @Basic
    @Column(name = "EMAIL")
    private String email;

    @Basic
    @Column(name = "ACCOUNTTYPE")
    private String accounttype;

    @Basic
    @Column(name = "NEWACCOUNT")
    private String newaccount;

    @Basic
    @Column(name = "ACCOUNT")
    private String account;

    @Basic
    @Column(name = "TYPE")
    private String type;

    @Basic
    @Column(name = "TIME_STAMP")
    private Date timeStamp;

    public String getGuid() {
        return guid;
    }

    public void setGuid(String guid) {
        this.guid = guid;
    }

    public String getPwd() {
        return pwd;
    }

    public void setPwd(String pwd) {
        this.pwd = pwd;
    }

    public String getSeqno() {
        return seqno;
    }

    public void setSeqno(String seqno) {
        this.seqno = seqno;
    }

    public String getCardid() {
        return cardid;
    }

    public void setCardid(String cardid) {
        this.cardid = cardid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getTel() {
        return tel;
    }

    public void setTel(String tel) {
        this.tel = tel;
    }

    public String getOperdate() {
        return operdate;
    }

    public void setOperdate(String operdate) {
        this.operdate = operdate;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getAccounttype() {
        return accounttype;
    }

    public void setAccounttype(String accounttype) {
        this.accounttype = accounttype;
    }

    public String getNewaccount() {
        return newaccount;
    }

    public void setNewaccount(String newaccount) {
        this.newaccount = newaccount;
    }

    public String getAccount() {
        return account;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Date getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(Date timeStamp) {
        this.timeStamp = timeStamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserAccount that = (UserAccount) o;
        return Objects.equals(guid, that.guid) &&
                Objects.equals(pwd, that.pwd) &&
                Objects.equals(seqno, that.seqno) &&
                Objects.equals(cardid, that.cardid) &&
                Objects.equals(name, that.name) &&
                Objects.equals(tel, that.tel) &&
                Objects.equals(operdate, that.operdate) &&
                Objects.equals(email, that.email) &&
                Objects.equals(accounttype, that.accounttype) &&
                Objects.equals(newaccount, that.newaccount) &&
                Objects.equals(account, that.account) &&
                Objects.equals(type, that.type) &&
                Objects.equals(timeStamp, that.timeStamp);
    }

    @Override
    public int hashCode() {

        return Objects.hash(guid, pwd, seqno, cardid, name, tel, operdate, email, accounttype, newaccount, account, type, timeStamp);
    }

    @Transient
    List<GrantedAuthority> grantedAuthorities=new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (grantedAuthorities.size()==0){
            grantedAuthorities.add(new SimpleGrantedAuthority("AUTH_0"));
        }
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return pwd;
    }

    public void setPassword(String password){
        this.pwd=password;
    }

    @Override
    public String getUsername() {
        return account;
    }

    public void setUsername(String username){
        this.account=username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
