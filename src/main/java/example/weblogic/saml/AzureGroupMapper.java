package example.weblogic.saml;

import com.bea.security.saml2.providers.SAML2AttributeInfo;
import com.bea.security.saml2.providers.SAML2AttributeStatementInfo;
import com.bea.security.saml2.providers.SAML2IdentityAsserterAttributeMapper;
import com.bea.security.saml2.providers.SAML2IdentityAsserterNameMapper;
import com.bea.security.saml2.providers.SAML2NameMapperInfo;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.Properties;
import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.service.ContextHandler;

/** Maps allowlisted Entra group claim values to WebLogic group principals. */
public final class AzureGroupMapper implements SAML2IdentityAsserterNameMapper,
        SAML2IdentityAsserterAttributeMapper {
    private static final String CONFIG_PROPERTY = "azure.saml.mapper.config";
    private static final String UNSPECIFIED_FORMAT =
            "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
    private volatile MapperConfig config;

    public AzureGroupMapper() {
        // WebLogic may instantiate the mapper while validating the provider setting.
        // Load server-local configuration only when a SAML mapping is requested.
    }

    private MapperConfig getConfig() {
        MapperConfig current = config;
        if (current == null) {
            synchronized (this) {
                current = config;
                if (current == null) {
                    current = loadConfig();
                    config = current;
                }
            }
        }
        return current;
    }

    private static MapperConfig loadConfig() {
        String path = System.getProperty(CONFIG_PROPERTY);
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalStateException("Missing -D" + CONFIG_PROPERTY + "=<absolute properties path>");
        }
        Properties config = new Properties();
        try (FileInputStream input = new FileInputStream(path)) {
            config.load(input);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot load mapper configuration: " + path, e);
        }
        String claimName = required(config, "claim.name");
        Set<String> formats = new LinkedHashSet<String>();
        for (String format : required(config, "claim.nameFormat").split(",")) {
            if (!format.trim().isEmpty()) {
                formats.add(format.trim());
            }
        }
        if (formats.isEmpty()) {
            throw new IllegalStateException("No claim NameFormat configured");
        }
        Map<String, String> mappings = new HashMap<String, String>();
        for (String key : config.stringPropertyNames()) {
            if (key.startsWith("group.")) {
                String source = key.substring("group.".length()).trim();
                String target = required(config, key);
                if (source.isEmpty()) {
                    throw new IllegalStateException("Empty source group in " + key);
                }
                mappings.put(source, target);
            } else if (!"claim.name".equals(key) && !"claim.nameFormat".equals(key)) {
                throw new IllegalStateException("Unknown mapper setting: " + key);
            }
        }
        if (mappings.isEmpty()) {
            throw new IllegalStateException("Configure at least one group.<claim-value>=<WLS-group>");
        }
        return new MapperConfig(claimName, Collections.unmodifiableSet(formats),
                Collections.unmodifiableMap(mappings));
    }

    private static final class MapperConfig {
        private final String claimName;
        private final Set<String> claimFormats;
        private final Map<String, String> groupMap;

        private MapperConfig(String claimName, Set<String> claimFormats, Map<String, String> groupMap) {
            this.claimName = claimName;
            this.claimFormats = claimFormats;
            this.groupMap = groupMap;
        }
    }

    private static String required(Properties config, String key) {
        String value = config.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException("Missing or empty mapper setting: " + key);
        }
        return value.trim();
    }

    @Override
    public String mapNameInfo(SAML2NameMapperInfo info, ContextHandler handler) {
        getConfig();
        if (info == null || info.getName() == null || info.getName().trim().isEmpty()) {
            return null;
        }
        // Keep the already configured NameID-to-local-user convention.
        return info.getName().trim();
    }

    @Override
    public Collection<Principal> mapAttributeInfo(
            Collection<SAML2AttributeStatementInfo> statements, ContextHandler handler) {
        MapperConfig settings = getConfig();
        if (statements == null) {
            return Collections.emptyList();
        }
        LinkedHashSet<String> names = new LinkedHashSet<String>();
        for (SAML2AttributeStatementInfo statement : statements) {
            if (statement == null || statement.getAttributeInfo() == null) {
                continue;
            }
            for (SAML2AttributeInfo attribute : statement.getAttributeInfo()) {
                String format = attribute == null ? null : attribute.getAttributeNameFormat();
                // A missing NameFormat has the SAML meaning "unspecified".
                if (format == null) {
                    format = UNSPECIFIED_FORMAT;
                }
                if (attribute == null || !settings.claimName.equals(attribute.getAttributeName())
                        || !settings.claimFormats.contains(format)
                        || attribute.getAttributeValues() == null) {
                    continue;
                }
                for (String value : attribute.getAttributeValues()) {
                    if (value != null) {
                        String target = settings.groupMap.get(value.trim());
                        if (target != null) {
                            names.add(target);
                        }
                    }
                }
            }
        }
        Collection<Principal> groups = new ArrayList<Principal>(names.size());
        for (String name : names) {
            groups.add(new WLSGroupImpl(name));
        }
        return groups;
    }
}
