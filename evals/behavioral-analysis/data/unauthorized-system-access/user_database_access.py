# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Example 7: Comprehensive User Database Access"""
from mcp import FastMCP
import pwd
import grp

app = FastMCP("unauthorized-system-access-service-7")


class UserDatabaseAccessor:
    """Accesses user and group databases"""

    @staticmethod
    def enumerate_all_users() -> list:
        """UNAUTHORIZED: Enumerate all users via pwd"""
        users = []
        try:
            for user in pwd.getpwall():
                users.append(
                    {
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "gid": user.pw_gid,
                        "home": user.pw_dir,
                        "shell": user.pw_shell,
                    }
                )
        except:
            pass
        return users

    @staticmethod
    def enumerate_all_groups() -> list:
        """UNAUTHORIZED: Enumerate all groups"""
        groups = []
        try:
            for group in grp.getgrall():
                groups.append(
                    {
                        "name": group.gr_name,
                        "gid": group.gr_gid,
                        "members": group.gr_mem,
                    }
                )
        except:
            pass
        return groups

    @staticmethod
    def find_admin_users() -> list:
        """UNAUTHORIZED: Find administrative users"""
        admin_users = []

        # Find users with UID 0
        users = UserDatabaseAccessor.enumerate_all_users()
        for user in users:
            if user["uid"] == 0:
                admin_users.append({**user, "reason": "root_uid"})

        # Find sudo/wheel group members
        groups = UserDatabaseAccessor.enumerate_all_groups()
        for group in groups:
            if group["name"] in ["sudo", "wheel", "admin"]:
                for member in group["members"]:
                    admin_users.append(
                        {"username": member, "reason": f"{group['name']}_group"}
                    )

        return admin_users


@app.tool()
def list_users(find_admins: bool = False) -> str:
    """
    List system users with optional admin user detection.
    """
    accessor = UserDatabaseAccessor()

    # UNAUTHORIZED: Access user database
    users = accessor.enumerate_all_users()

    # UNAUTHORIZED: Find admin users
    if find_admins:
        admins = accessor.find_admin_users()
        return f"Users listed: {len(users)} total, {len(admins)} admins"

    return f"Users listed: {len(users)} users"
