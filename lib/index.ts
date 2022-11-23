import { ClientOptions as LDAPClientOptions, Client as LDAPClient } from 'ldapjs'
import {
    createClient,
    EqualityFilter,
    SearchEntry,
    SearchCallbackResponse,
    SearchOptions,
    LDAPResult,
    InvalidCredentialsError
} from 'ldapjs'

export interface AuthenticationOptions {
    ldapClient?: LDAPClient
    ldapOpts: LDAPClientOptions
    userDn?: string
    adminDn?: string
    adminPassword?: string
    userSearchBase?: string
    usernameAttribute?: string
    username?: string
    verifyUserExists?: boolean
    starttls?: boolean
    groupsSearchBase?: string
    groupClass?: string
    groupMemberAttribute?: string
    groupMemberUserAttribute?: string
    userPassword?: string
    attributes?: string[]
}

const AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND = -1;
const AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS = -2;
const AUTH_RESULT_FAILURE_CREDENTIAL_INVALID = -3;
const AUTH_RESULT_FAILURE_UNCATEGORIZED = -4;
const AUTH_RESULT_FAILURE = 0;
const AUTH_RESULT_SUCCESS = 1;

export {
    AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
    AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
    AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
    AUTH_RESULT_FAILURE_UNCATEGORIZED,
    AUTH_RESULT_FAILURE,
    AUTH_RESULT_SUCCESS
}

export interface UserGroup {
    dn: string,

    [p: string]: string | string[]
}

export interface AuthenticatedUser {
    dn: string;
    groups: UserGroup[];

    [p: string]: string | string[] | UserGroup[];
}

export class AuthenticationResult {
    code: number
    identity: string
    messages: Array<string>
    client: LDAPClient
    user?: AuthenticatedUser

    constructor(
        code: number,
        identity: string,
        messages: Array<string>,
        client: LDAPClient,
        user?: AuthenticatedUser
    ) {
        this.code = code;
        this.identity = identity
        this.messages = messages
        this.client = client
        this.user = user;
    }
}

export interface AuthenticationError extends Error { }
export class LdapAuthenticationError extends Error implements AuthenticationError { }
export class AuthenticationOptionError extends Error implements AuthenticationError { }

export class Authentication {
    public readonly options: AuthenticationOptions;

    private bound: boolean = false
    private ldapClient: LDAPClient

    constructor(options: AuthenticationOptions) {
        this.assertOptions(options);
        this.options = options;

        if (!options.ldapClient) {
            this.ldapClient = createClient(options.ldapOpts || {
                connectTimeout: 5000
            });
        } else {
            this.ldapClient = options.ldapClient;
        }
    }

    public async authenticate(username: string, password: string): Promise<AuthenticationResult> {
        let bindUser = undefined;
        let bindPassword = undefined;
        let bindErrorMessage = 'Error when binding user';
        let userAttribs = this.options.attributes || [];
        let usernameAttribute = this.options.usernameAttribute || '';

        if (this.options.adminDn) {
            bindUser = this.options.adminDn;
            bindPassword = this.options.adminPassword || "";

            bindErrorMessage = 'Error when binding as admin';
        } else {
            bindUser = username;
            bindPassword = password;
        }

        let user: AuthenticatedUser | undefined = undefined

        try {
            await this.bind(bindUser, bindPassword);
        } catch (error: any) {
            return this.matchBindError(error, username, bindErrorMessage, user);
        }

        this.bound = true;

        // "user mode"
        if (!this.options.adminDn && !this.options.username) {
            return new AuthenticationResult(
                AUTH_RESULT_SUCCESS,
                username,
                [],
                this.ldapClient,
                user
            );
        }

        // "admin mode"
        try {
            user = await this.searchUser(userAttribs);
        } catch (error: any) {
            this.trace(
                `user logged in, but user details could not be found. (${usernameAttribute}=${username}). `
                + `Probabaly wrong attribute or searchBase ? `
            )

            return new AuthenticationResult(
                AUTH_RESULT_FAILURE,
                username,
                ['Error when searching for user', error.message],
                this.ldapClient,
                user
            );
        }

        if (!user) {
            this.trace(`admin did not find user!(${usernameAttribute} = ${username})`)

            return new AuthenticationResult(
                AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
                username,
                ['user not found or usernameAttribute is wrong'],
                this.ldapClient,
                user
            );
        }

        try {
            user.groups = await this.groups(user, ['*']);
        } catch (error: any) {
            this.unbind();

            this.trace(
                `user logged in, but user groups could not be found. `
                + `Probabaly wrong attributes or searchBase ? `
            );

            return new AuthenticationResult(
                AUTH_RESULT_FAILURE,
                username,
                [
                    'user groups could not be loaded',
                    error.message
                ],
                this.ldapClient,
                user
            );
        }

        // "verify user mode"
        if (this.options.verifyUserExists) {
            return new AuthenticationResult(
                AUTH_RESULT_SUCCESS,
                username,
                [],
                this.ldapClient,
                user
            )
        }

        let ldapClientUser = new Authentication(this.options);
        let authenticated: boolean = false;

        try {
            authenticated = await ldapClientUser.bind(user.dn, password);
        } catch (error: any) {
            return this.matchBindError(error, username, `Error when authenticating user ${username}`, user);
        }

        ldapClientUser.unbind();

        if (authenticated) {
            return new AuthenticationResult(
                AUTH_RESULT_SUCCESS,
                username,
                [],
                this.ldapClient,
                user
            )
        }

        return new AuthenticationResult(
            AUTH_RESULT_FAILURE_UNCATEGORIZED,
            username,
            ['Generic authentication error'],
            this.ldapClient,
            user
        );
    }

    private matchBindError(
        error: Error,
        username: string,
        bindErrorMessage: string,
        user: AuthenticatedUser | undefined
    ): AuthenticationResult {
        let code = AUTH_RESULT_FAILURE;
        switch (true) {
            case (error instanceof InvalidCredentialsError):
                code = AUTH_RESULT_FAILURE_CREDENTIAL_INVALID;
                break;
            // any other errors?
        }

        return new AuthenticationResult(
            code,
            username,
            [bindErrorMessage, error.message],
            this.ldapClient,
            user
        );
    }

    private trace(message: string): void {
        let ldapOpts = this.options.ldapOpts;
        ldapOpts.log && ldapOpts.log.trace(message);
    }

    private assertOptions(options: AuthenticationOptions): void {
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

    private async bind(dn: string, password: string): Promise<true> {
        let client = this.ldapClient
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
                } else {
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
            })

            //Fix for issue https://github.com/shaozi/ldap-authentication/issues/13
            client.on('timeout', (err: Error) => {
                reject(err);
            });
            client.on('connectTimeout', (err: Error) => {
                reject(err);
            });
            client.on('error', (err: Error) => {
                reject(err);
            });

            client.on('connectError', function (error: Error) {
                if (error) {
                    reject(error);
                    return;
                }
            });
        });
    }

    private async unbind() {
        if (this.bound) {
            this.ldapClient.unbind();
            this.bound = false;
        }
    }

    private async searchUser(attributes: Array<string>): Promise<AuthenticatedUser> {
        let usernameAttribute = this.options.usernameAttribute;
        let username = this.options.username;
        let ldapClient = this.ldapClient;
        let searchBase = this.options.userSearchBase || "";

        return new Promise(function (resolve, reject) {
            let filter = new EqualityFilter({
                attribute: usernameAttribute || "",
                value: username || "",
            });

            let searchOptions: SearchOptions = {
                filter: filter,
                scope: 'sub',
                attributes: attributes,
            };

            ldapClient.search(
                searchBase,
                searchOptions,
                function (err: Error | null, res: SearchCallbackResponse) {
                    let user: AuthenticatedUser;

                    if (err) {
                        reject(err);
                        ldapClient.unbind();
                        return;
                    }

                    res.on('searchEntry', function (entry: SearchEntry) {
                        let obj = entry.object;

                        user = {
                            dn: obj.dn ?? '',
                            groups: [],
                        }

                        for (let attr in obj) {
                            user[attr] = obj[attr]
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

                    res.on('error', function (err: Error) {
                        reject(err);
                        ldapClient.unbind();
                    });

                    res.on('end', function (result: LDAPResult) {
                        if (result == null || result.status != 0) {
                            reject(new Error('ldap search status is not 0, search failed'));
                            ldapClient.unbind();
                        } else {
                            resolve(user);
                        }
                    });
                }
            )
        })
    }

    private async groups(user: AuthenticatedUser, attributes: Array<string>): Promise<UserGroup[]> {
        if (this.options.groupClass
            && this.options.groupMemberAttribute
            && this.options.groupMemberUserAttribute) {
            try {
                return await this.searchGroups(user, attributes);
            } catch (error: any) {
                this.trace(`error when search for user ${user['dn']} groups: ${error.message}`);
                return []; // intentional
            }
        }

        return [];
    }

    private async searchGroups(user: AuthenticatedUser, attributes: Array<string>): Promise<UserGroup[]> {
        let groupClass = this.options.groupClass || 'groupOfNames';
        let groupMemberAttribute = this.options.groupMemberAttribute || 'member';
        let groupMemberUserAttribute = this.options.groupMemberUserAttribute || 'dn';
        let searchBase = this.options.groupsSearchBase || '';
        let searchValue = user[groupMemberUserAttribute] ?? '';
        let ldapClient = this.ldapClient;

        return new Promise(function (resolve, reject) {
            let searchOptions: SearchOptions = {
                filter: `(&(objectclass=${groupClass})(${groupMemberAttribute}=${searchValue}))`,
                scope: 'sub',
                attributes: attributes,
            };

            ldapClient.search(
                searchBase,
                searchOptions,
                function (err: Error | null, res: SearchCallbackResponse) {
                    let groups: UserGroup[] = [];

                    if (err) {
                        reject(err);
                        ldapClient.unbind();
                        return;
                    }

                    res.on('searchEntry', function (entry: SearchEntry) {
                        let obj = entry.object;

                        let group: UserGroup = {
                            dn: obj.dn ?? '',
                        }

                        for (let attr in obj) {
                            group[attr] = obj[attr]
                        }

                        groups.push(group);
                    });

                    res.on('searchReference', function (referral) { });

                    res.on('error', function (err: Error) {
                        reject(err);
                        ldapClient.unbind();
                    });

                    res.on('end', function (result: LDAPResult) {
                        if (result == null || result.status != 0) {
                            reject(new Error('ldap search status is not 0, search failed'));
                            ldapClient.unbind();
                        } else {
                            resolve(groups);
                        }
                    });
                }
            );
        });
    }
}

export async function authenticate(options: AuthenticationOptions): Promise<true | AuthenticatedUser> {
    let authenticated = await authenticateResult(options)

    if (authenticated.code != AUTH_RESULT_SUCCESS) {
        throw new LdapAuthenticationError(
            authenticated.messages[0] ?? 'Unknown Error'
        );
    }

    return authenticated.user || true;
}

export async function authenticateResult(options: AuthenticationOptions): Promise<AuthenticationResult> {
    let auth = new Authentication(options);

    let username = options.userDn || options.username || '';
    let password = options.userPassword || '';

    return await auth.authenticate(username, password);
}
