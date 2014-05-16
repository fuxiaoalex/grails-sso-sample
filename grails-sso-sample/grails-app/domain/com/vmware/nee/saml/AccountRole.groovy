package com.vmware.nee.saml

import org.apache.commons.lang.builder.HashCodeBuilder

class AccountRole implements Serializable {

	private static final long serialVersionUID = 1

	Account account
	Role role

	boolean equals(other) {
		if (!(other instanceof AccountRole)) {
			return false
		}

		other.account?.id == account?.id &&
			other.role?.id == role?.id
	}

	int hashCode() {
		def builder = new HashCodeBuilder()
		if (account) builder.append(account.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static AccountRole get(long accountId, long roleId) {
		AccountRole.where {
			account == Account.load(accountId) &&
			role == Role.load(roleId)
		}.get()
	}

	static AccountRole create(Account account, Role role, boolean flush = false) {
		new AccountRole(account: account, role: role).save(flush: flush, insert: true)
	}

	static boolean remove(Account u, Role r, boolean flush = false) {

		int rowCount = AccountRole.where {
			account == Account.load(u.id) &&
			role == Role.load(r.id)
		}.deleteAll()

		rowCount > 0
	}

	static void removeAll(Account u) {
		AccountRole.where {
			account == Account.load(u.id)
		}.deleteAll()
	}

	static void removeAll(Role r) {
		AccountRole.where {
			role == Role.load(r.id)
		}.deleteAll()
	}

	static mapping = {
		id composite: ['role', 'account']
		version false
	}
}
