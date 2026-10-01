# Azure SAML group mapper for WebLogic Server

A custom SAML 2.0 Identity Asserter mapper that reads an incoming Microsoft Entra ID group claim and adds selected group values as `WLSGroupImpl` principals to the authenticated WebLogic subject. It does not change the signed SAML assertion. This example builds on [Oracle's SAML 2.0 identity asserter attribute mapper documentation](https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/scprg/saml.html#GUID-3808A141-AD00-4F59-B085-FD1AB2B3422A).

The example claim value `puneeth_group` is a placeholder. Replace it with values from your environment. Do not commit live SAML assertions or your server-local properties file.

**Detailed walkthrough:** [How to Add Azure Groups as Principals to a WebLogic Subject in SAML SSO](https://blogbypuneeth.medium.com/how-to-add-azure-groups-as-principals-to-a-weblogic-subject-when-azure-and-wls-are-integrated-with-5ccbd5626fd2)

## Files

- `src/main/java/example/weblogic/saml/AzureGroupMapper.java` — the mapper.
- `config/azure-group-mapper.properties.example` — sample configuration.

## Configure the mapping

Copy the example properties file to a server-local location named `azure-group-mapper.properties`. Set `claim.name` to the exact SAML attribute name and add one `group.<incoming-value>=<WebLogic-group>` entry for each allowed group. For the sample assertion:

```properties
claim.name=http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
claim.nameFormat=urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified,urn:oasis:names:tc:SAML:2.0:attrname-format:basic
group.puneeth_group=puneeth_group
```

The value after `group.` is what arrives in the SAML claim; the value after `=` is the WebLogic principal name. The mapper ignores group values without a matching entry. A missing SAML `NameFormat` is treated as `unspecified`.

## Compile manually

Run from the repository root with a JDK and the `weblogic.jar` from your WebLogic installation. Replace the two example paths:

```bash
export JAVA_HOME=/path/to/jdk-21
export WLS_HOME=/path/to/oracle_home/wlserver
mkdir -p build/classes dist
"$JAVA_HOME/bin/javac" --release 8 -cp "$WLS_HOME/server/lib/weblogic.jar" -d build/classes src/main/java/example/weblogic/saml/AzureGroupMapper.java
"$JAVA_HOME/bin/jar" cf dist/azure-group-mapper.jar -C build/classes .
```

For JDK 8, replace `--release 8` with `-source 8 -target 8`. The class targets Java 8 bytecode; use a JDK certified for your WebLogic release at runtime.

## Install in WebLogic

1. Put the mapper JAR on the **system classpath** of the Admin Server and every Managed Server that handles SAML login. `DOMAIN_HOME/lib` alone does not make the class visible to this security provider.
2. Give each server this JVM system property, pointing to its server-local configuration file:

   ```text
   -Dazure.saml.mapper.config=/path/to/azure-group-mapper.properties
   ```

   This is a property read by `AzureGroupMapper`, not a built-in WebLogic flag.
3. In the active realm's **SAML 2.0 Identity Asserter**, set **Name Mapper Class Name** to `example.weblogic.saml.AzureGroupMapper`.
4. Enable **Virtual User** for the Entra IdP partner and configure the **SAML Authentication provider** so assertion groups can enter the subject. Save, activate, and restart the affected servers. See [Oracle's SAML Authentication provider guidance](https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/14.1.2/secmg/saml_atn.html).
5. Sign in with a new SAML session and check the final subject for `WLSGroupImpl("puneeth_group")`. Also test a user outside the mapped group and confirm that principal is absent.

## Security notes

The mapper accepts only configured claim values. It does not create persistent WebLogic groups or application access policies. Keep real group mappings and SAML responses out of this public repository.
