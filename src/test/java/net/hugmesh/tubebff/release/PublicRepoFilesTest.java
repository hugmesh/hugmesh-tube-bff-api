package net.hugmesh.tubebff.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the files a PUBLIC repository needs before anyone outside can use or report on it.
 *
 * <ul>
 *   <li><b>LICENSE.</b> A public repository with no license is "all rights reserved": anyone
 *       may read it, nobody may legally reuse it. The org licence is MIT.</li>
 *   <li><b>pom.xml {@code <licenses>}.</b> Maven tooling reads the pom, not the file, so the
 *       pom must name the SAME licence. hugmesh-parent declares none, so nothing is inherited.
 *       The pom is read PARSED and only direct children of {@code <project>} count, so a
 *       licence named in a comment or in some plugin's configuration does not satisfy it.</li>
 *   <li><b>SECURITY.md.</b> Tells an outside finder to report privately, not in a public
 *       issue.</li>
 * </ul>
 */
class PublicRepoFilesTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final String LICENSE_NAME = "MIT License";

    private static List<Element> children(Element parent, String tag) {
        List<Element> out = new ArrayList<>();
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node kid = kids.item(i);
            if (kid.getNodeType() == Node.ELEMENT_NODE && tag.equals(kid.getNodeName())) {
                out.add((Element) kid);
            }
        }
        return out;
    }

    @Test
    @DisplayName("LICENSE exists at the repo root and is the MIT licence")
    void licenseFileIsMit() throws Exception {
        Path license = ROOT.resolve("LICENSE");
        assertThat(license).as("LICENSE at the repo root").isRegularFile();
        String text = Files.readString(license, StandardCharsets.UTF_8);
        assertThat(text.strip()).startsWith(LICENSE_NAME);
        assertThat(text).contains("Permission is hereby granted, free of charge");
    }

    @Test
    @DisplayName("pom.xml names the same licence as the LICENSE file")
    void pomDeclaresTheSameLicence() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc = f.newDocumentBuilder().parse(ROOT.resolve("pom.xml").toFile());
        Element project = doc.getDocumentElement();

        List<Element> licensesBlocks = children(project, "licenses");
        assertThat(licensesBlocks).as("<project><licenses>").hasSize(1);
        List<Element> licenses = children(licensesBlocks.get(0), "license");
        assertThat(licenses).as("<licenses><license>").hasSize(1);
        List<Element> names = children(licenses.get(0), "name");
        assertThat(names).as("<license><name>").hasSize(1);
        assertThat(names.get(0).getTextContent().strip()).isEqualTo(LICENSE_NAME);
    }

    @Test
    @DisplayName("SECURITY.md routes vulnerability reports to private reporting")
    void securityPolicyPointsAtPrivateReporting() throws Exception {
        Path security = ROOT.resolve("SECURITY.md");
        assertThat(security).as("SECURITY.md at the repo root").isRegularFile();
        String text = Files.readString(security, StandardCharsets.UTF_8);
        assertThat(text).contains("private vulnerability reporting");
        assertThat(text).contains("Do not open a public issue");
    }
}
