// OpenSourceLicensesView.swift — Settings → Info → "Open-source licenses".
// The license of LADON messenger itself (AGPL v3.0) and the notices of every
// bundled third-party component. The BSD licenses of Tor, SQLCipher, libevent,
// lyrebird and Snowflake require these notices when the app ships them in
// binary form. Texts live in OpenSourceLicenses.swift.

import SwiftUI

struct OpenSourceLicensesView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    private var isDark: Bool { AppearanceManager.isDarkStored }

    /// Shown as text, not as a link: opening it would leave Tor.
    private let sourceURL = "github.com/LADONmessenger/ladon-messenger"

    var body: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 22) {
                GlassSection(header: "LADON messenger") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("LADON messenger is free software, licensed under the GNU Affero General Public License v3.0.")
                            .font(isDark ? .body : .manrope(15, .medium))
                            .foregroundColor(LadonTheme.textPrimary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Source code")
                                .font(.caption)
                                .foregroundColor(LadonTheme.textSecondary)
                            Text(verbatim: sourceURL)
                                .font(.jbMono(12, relativeTo: .caption))
                                .foregroundColor(LadonTheme.textPrimary)
                                .textSelection(.enabled)
                        }
                        CardDivider()
                        componentRow(OpenSourceLicenses.app)
                    }
                    .padding(16)
                }

                GlassSection(header: "Third-party components") {
                    VStack(spacing: 0) {
                        ForEach(Array(OpenSourceLicenses.components.enumerated()), id: \.element.id) { idx, component in
                            componentRow(component)
                                .padding(.horizontal, 16).padding(.vertical, 12)
                            if idx < OpenSourceLicenses.components.count - 1 {
                                CardDivider()
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 16)
        }
        }
        .navigationTitle("Open-source licenses")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
    }

    private func componentRow(_ component: OpenSourceComponent) -> some View {
        NavigationLink {
            LicenseTextView(component: component)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: component.name)
                        .font(isDark ? .body : .manrope(15.5, .bold))
                        .foregroundColor(LadonTheme.textPrimary)
                    Text(verbatim: component.version.isEmpty
                         ? component.license
                         : "\(component.license) · \(component.version)")
                        .font(.caption)
                        .foregroundColor(LadonTheme.textSecondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(LadonTheme.inkMuted)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// The full license text of one component, verbatim.
private struct LicenseTextView: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let component: OpenSourceComponent

    var body: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            GlassSection {
                Text(verbatim: component.text)
                    .font(.jbMono(11, relativeTo: .footnote))
                    .foregroundColor(LadonTheme.textPrimary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 16)
        }
        }
        .navigationTitle(Text(verbatim: component.name))
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
    }
}
