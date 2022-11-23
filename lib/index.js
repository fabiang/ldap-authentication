"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateResult = exports.authenticate = exports.Authentication = exports.AuthenticationOptionError = exports.LdapAuthenticationError = exports.AuthenticationResult = exports.AUTH_RESULT_SUCCESS = exports.AUTH_RESULT_FAILURE = exports.AUTH_RESULT_FAILURE_UNCATEGORIZED = exports.AUTH_RESULT_FAILURE_CREDENTIAL_INVALID = exports.AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS = exports.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND = void 0;
const ldapjs_1 = require("ldapjs");
const AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND = -1;
exports.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND = AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND;
const AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS = -2;
exports.AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS = AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS;
const AUTH_RESULT_FAILURE_CREDENTIAL_INVALID = -3;
exports.AUTH_RESULT_FAILURE_CREDENTIAL_INVALID = AUTH_RESULT_FAILURE_CREDENTIAL_INVALID;
const AUTH_RESULT_FAILURE_UNCATEGORIZED = -4;
exports.AUTH_RESULT_FAILURE_UNCATEGORIZED = AUTH_RESULT_FAILURE_UNCATEGORIZED;
const AUTH_RESULT_FAILURE = 0;
exports.AUTH_RESULT_FAILURE = AUTH_RESULT_FAILURE;
const AUTH_RESULT_SUCCESS = 1;
exports.AUTH_RESULT_SUCCESS = AUTH_RESULT_SUCCESS;
class AuthenticationResult {
    constructor(code, identity, messages, client, user) {
        this.code = code;
        this.identity = identity;
        this.messages = messages;
        this.client = client;
        this.user = user;
    }
}
exports.AuthenticationResult = AuthenticationResult;
class LdapAuthenticationError extends Error {
}
exports.LdapAuthenticationError = LdapAuthenticationError;
class AuthenticationOptionError extends Error {
}
exports.AuthenticationOptionError = AuthenticationOptionError;
class Authentication {
    constructor(options) {
        this.bound = false;
        this.assertOptions(options);
        this.options = options;
        if (!options.ldapClient) {
            this.ldapClient = ldapjs_1.createClient(options.ldapOpts || {
                connectTimeout: 5000
            });
        }
        else {
            this.ldapClient = options.ldapClient;
        }
    }
    async authenticate(username, password) {
        let bindUser = undefined;
        let bindPassword = undefined;
        let bindErrorMessage = 'Error when binding user';
        let userAttribs = this.options.attributes || [];
        let usernameAttribute = this.options.usernameAttribute || '';
        if (this.options.adminDn) {
            bindUser = this.options.adminDn;
            bindPassword = this.options.adminPassword || "";
            bindErrorMessage = 'Error when binding as admin';
        }
        else {
            bindUser = username;
            bindPassword = password;
        }
        let user = undefined;
        try {
            await this.bind(bindUser, bindPassword);
        }
        catch (error) {
            return this.matchBindError(error, username, bindErrorMessage, user);
        }
        this.bound = true;
        // "user mode"
        if (!this.options.adminDn && !this.options.username) {
            return new AuthenticationResult(AUTH_RESULT_SUCCESS, username, [], this.ldapClient, user);
        }
        // "admin mode"
        try {
            user = await this.searchUser(userAttribs);
        }
        catch (error) {
            this.trace(`user logged in, but user details could not be found. (${usernameAttribute}=${username}). `
                + `Probabaly wrong attribute or searchBase ? `);
            return new AuthenticationResult(AUTH_RESULT_FAILURE, username, ['Error when searching for user', error.message], this.ldapClient, user);
        }
        if (!user) {
            this.trace(`admin did not find user!(${usernameAttribute} = ${username})`);
            return new AuthenticationResult(AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND, username, ['user not found or usernameAttribute is wrong'], this.ldapClient, user);
        }
        try {
            user.groups = await this.groups(user, ['*']);
        }
        catch (error) {
            this.unbind();
            this.trace(`user logged in, but user groups could not be found. `
                + `Probabaly wrong attributes or searchBase ? `);
            return new AuthenticationResult(AUTH_RESULT_FAILURE, username, [
                'user groups could not be loaded',
                error.message
            ], this.ldapClient, user);
        }
        // "verify user mode"
        if (this.options.verifyUserExists) {
            return new AuthenticationResult(AUTH_RESULT_SUCCESS, username, [], this.ldapClient, user);
        }
        let ldapClientUser = new Authentication(this.options);
        let authenticated = false;
        try {
            authenticated = await ldapClientUser.bind(user.dn, password);
        }
        catch (error) {
            return this.matchBindError(error, username, `Error when authenticating user ${username}`, user);
        }
        ldapClientUser.unbind();
        if (authenticated) {
            return new AuthenticationResult(AUTH_RESULT_SUCCESS, username, [], this.ldapClient, user);
        }
        return new AuthenticationResult(AUTH_RESULT_FAILURE_UNCATEGORIZED, username, ['Generic authentication error'], this.ldapClient, user);
    }
    matchBindError(error, username, bindErrorMessage, user) {
        let code = AUTH_RESULT_FAILURE;
        switch (true) {
            case (error instanceof ldapjs_1.InvalidCredentialsError):
                code = AUTH_RESULT_FAILURE_CREDENTIAL_INVALID;
                break;
            // any other errors?
        }
        return new AuthenticationResult(code, username, [bindErrorMessage, error.message], this.ldapClient, user);
    }
    trace(message) {
        let ldapOpts = this.options.ldapOpts;
        ldapOpts.log && ldapOpts.log.trace(message);
    }
    assertOptions(options) {
        if (!options.ldapOpts || !options.ldapOpts.url) {
            throw new AuthenticationOptionError('ldapOpts.url must be provided');
        }
        if (!options.userDn && !options.adminDn) {
            throw new AuthenticationOptionError('adminDn/adminPassword OR userDn must be provided');
        }
        if (options.verifyUserExists) {
            if (!options.adminDn) {
                throw new AuthenticationOptionError('Admin mode adminDn must be provided');
            }
            if (!options.adminPassword) {
                throw new AuthenticationOptionError('adminDn and adminPassword must be both provided.');
            }
        }
        if (!options.userDn) {
            if (!options.adminPassword) {
                throw new AuthenticationOptionError('Admin mode adminPassword must be provided');
            }
            if (!options.userSearchBase) {
                throw new AuthenticationOptionError('Admin mode userSearchBase must be provided');
            }
            if (!options.usernameAttribute) {
                throw new AuthenticationOptionError('Admin mode usernameAttribute must be provided');
            }
            if (!options.username) {
                throw new AuthenticationOptionError('Admin mode username must be provided');
            }
        }
    }
    async bind(dn, password) {
        let client = this.ldapClient;
        let starttls = this.options.starttls;
        let ldapOpts = this.options.ldapOpts;
        let tlsOptions = ldapOpts.tlsOptions = {};
        return new Promise(function (resolve, reject) {
            client.on('connect', function () {
                if (starttls) {
                    client.starttls(tlsOptions, null, function (error) {
                        if (error) {
                            reject(error);
                            return;
                        }
                        client.bind(dn, password, function (err) {
                            if (err) {
                                reject(err);
                                client.unbind();
                                return;
                            }
                            ldapOpts.log && ldapOpts.log.trace('bind success!');
                            resolve(true);
                        });
                    });
                }
                else {
                    client.bind(dn, password, function (err) {
                        if (err) {
                            reject(err);
                            client.unbind();
                            return;
                        }
                        ldapOpts.log && ldapOpts.log.trace('bind success!');
                        resolve(true);
                    });
                }
            });
            //Fix for issue https://github.com/shaozi/ldap-authentication/issues/13
            client.on('timeout', (err) => {
                reject(err);
            });
            client.on('connectTimeout', (err) => {
                reject(err);
            });
            client.on('error', (err) => {
                reject(err);
            });
            client.on('connectError', function (error) {
                if (error) {
                    reject(error);
                    return;
                }
            });
        });
    }
    async unbind() {
        if (this.bound) {
            this.ldapClient.unbind();
            this.bound = false;
        }
    }
    async searchUser(attributes) {
        let usernameAttribute = this.options.usernameAttribute;
        let username = this.options.username;
        let ldapClient = this.ldapClient;
        let searchBase = this.options.userSearchBase || "";
        return new Promise(function (resolve, reject) {
            let filter = new ldapjs_1.EqualityFilter({
                attribute: usernameAttribute || "",
                value: username || "",
            });
            let searchOptions = {
                filter: filter,
                scope: 'sub',
                attributes: attributes,
            };
            ldapClient.search(searchBase, searchOptions, function (err, res) {
                let user;
                if (err) {
                    reject(err);
                    ldapClient.unbind();
                    return;
                }
                res.on('searchEntry', function (entry) {
                    let obj = entry.object;
                    user = {
                        dn: obj.dn ?? '',
                        groups: [],
                    };
                    for (let attr in obj) {
                        user[attr] = obj[attr];
                    }
                });
                res.on('searchReference', function (referral) {
                    // TODO: we don't support reference yet
                    // If the server was able to locate the entry referred to by the baseObject
                    // but could not search one or more non-local entries,
                    // the server may return one or more SearchResultReference messages,
                    // each containing a reference to another set of servers for continuing the operation.
                    // referral.uris
                });
                res.on('error', function (err) {
                    reject(err);
                    ldapClient.unbind();
                });
                res.on('end', function (result) {
                    if (result == null || result.status != 0) {
                        reject(new Error('ldap search status is not 0, search failed'));
                        ldapClient.unbind();
                    }
                    else {
                        resolve(user);
                    }
                });
            });
        });
    }
    async groups(user, attributes) {
        if (this.options.groupClass
            && this.options.groupMemberAttribute
            && this.options.groupMemberUserAttribute) {
            try {
                return await this.searchGroups(user, attributes);
            }
            catch (error) {
                this.trace(`error when search for user ${user['dn']} groups: ${error.message}`);
                return []; // intentional
            }
        }
        return [];
    }
    async searchGroups(user, attributes) {
        let groupClass = this.options.groupClass || 'groupOfNames';
        let groupMemberAttribute = this.options.groupMemberAttribute || 'member';
        let groupMemberUserAttribute = this.options.groupMemberUserAttribute || 'dn';
        let searchBase = this.options.groupsSearchBase || '';
        let searchValue = user[groupMemberUserAttribute] ?? '';
        let ldapClient = this.ldapClient;
        return new Promise(function (resolve, reject) {
            let searchOptions = {
                filter: `(&(objectclass=${groupClass})(${groupMemberAttribute}=${searchValue}))`,
                scope: 'sub',
                attributes: attributes,
            };
            ldapClient.search(searchBase, searchOptions, function (err, res) {
                let groups = [];
                if (err) {
                    reject(err);
                    ldapClient.unbind();
                    return;
                }
                res.on('searchEntry', function (entry) {
                    let obj = entry.object;
                    let group = {
                        dn: obj.dn ?? '',
                    };
                    for (let attr in obj) {
                        group[attr] = obj[attr];
                    }
                    groups.push(group);
                });
                res.on('searchReference', function (referral) { });
                res.on('error', function (err) {
                    reject(err);
                    ldapClient.unbind();
                });
                res.on('end', function (result) {
                    if (result == null || result.status != 0) {
                        reject(new Error('ldap search status is not 0, search failed'));
                        ldapClient.unbind();
                    }
                    else {
                        resolve(groups);
                    }
                });
            });
        });
    }
}
exports.Authentication = Authentication;
async function authenticate(options) {
    let authenticated = await authenticateResult(options);
    if (authenticated.code != AUTH_RESULT_SUCCESS) {
        throw new LdapAuthenticationError(authenticated.messages[0] ?? 'Unknown Error');
    }
    return authenticated.user || true;
}
exports.authenticate = authenticate;
async function authenticateResult(options) {
    let auth = new Authentication(options);
    let username = options.userDn || options.username || '';
    let password = options.userPassword || '';
    return await auth.authenticate(username, password);
}
exports.authenticateResult = authenticateResult;
//# sourceMappingURL=index.js.map