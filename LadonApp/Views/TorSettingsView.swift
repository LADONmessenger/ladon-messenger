//
//  TorSettingsView.swift
//  Ladon
//
//  Tor Network Settings & Controls
//

import SwiftUI

struct TorSettingsView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @StateObject private var torManager = TorManager.shared
    private var isDark: Bool { AppearanceManager.isDarkStored }

    /// Route icon. Dark = the original plain symbol; light draws the three
    /// relays as the site's dark "packet" tiles (they carry encrypted traffic).
    @ViewBuilder
    private func routeIcon(_ name: String, relay: Bool) -> some View {
        if isDark || !relay {
            Image(systemName: name).font(.title3)
        } else {
            Image(systemName: name)
                .font(.system(size: 15, weight: .medium))
                .foregroundColor(LadonTheme.greenInk)
                .frame(width: 38, height: 44)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(LadonTheme.packet))
        }
    }
    var body: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 22) {

                // Status
                GlassSection(header: "Status") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Image(systemName: torManager.isConnected ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundColor(torManager.isConnected ? LadonTheme.greenInk : LadonTheme.coralInk)
                                .font(.title2)

                            VStack(alignment: .leading, spacing: 4) {
                                Text("Tor Network")
                                    .font(isDark ? .headline : .manrope(15.5, .bold))
                                Text(torManager.statusMessage)
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.textSecondary)
                            }

                            Spacer()

                            if torManager.isStarting {
                                ProgressView()
                            }
                        }

                        if torManager.isStarting {
                            ProgressView(value: torManager.progress) {
                                Text("Bootstrapping...")
                            }
                            .tint(LadonTheme.brandGreen)
                        }

                        if torManager.errorMessage != nil {
                            // TS-01 FIX: Sanitize Tor errors — don't show raw error with paths/hostnames
                            Text("Connection error. Please check your network and try again.")
                                .font(.caption)
                                .foregroundColor(LadonTheme.coralInk)
                        }
                    }
                    .padding(16)
                }

                // Controls
                GlassSection(
                    header: "Controls",
                    footer: "Tor routes all network traffic through 3 encrypted relays for anonymity."
                ) {
                    VStack(spacing: 0) {
                        if !torManager.isConnected {
                            Button {
                                Task { await torManager.startTor() }
                            } label: {
                                Label("Start Tor", systemImage: "play.circle.fill")
                                    .foregroundColor(LadonTheme.greenInk)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(16)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(torManager.isStarting)
                        } else {
                            Button(role: .destructive) {
                                Task { await torManager.stopTor() }
                            } label: {
                                Label("Stop Tor", systemImage: "stop.circle.fill")
                                    .foregroundColor(LadonTheme.coralInk)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(16)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            CardDivider()
                            Button {
                                Task { await torManager.restartTor() }
                            } label: {
                                Label("New Circuit", systemImage: "arrow.triangle.2.circlepath")
                                    .foregroundColor(LadonTheme.greenInk)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(16)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                // 🔐 Tor Enforcement — mandatory, no opt-out (security principle #1).
                // P8-SEC-IOS-01 (2026-05-23): the disable-Tor toggle (+ biometric
                // gate) was retired. Tor is always required; this is now a status row.
                GlassSection(
                    header: "Privacy Protection",
                    footer: "Your messages are always routed through 3 encrypted relays so no one can trace who you're talking to. The connection is set up automatically when you open the app — messages wait until it's ready."
                ) {
                    VStack(alignment: .leading, spacing: 12) {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Anonymous Connection Required")
                                    .font(.body)
                                Text("Messages are always sent through Tor")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.greenInk)
                            }
                        } icon: {
                            Image(systemName: "lock.shield.fill")
                                .foregroundColor(LadonTheme.greenInk)
                        }

                        if !torManager.isConnected {
                            if torManager.isStarting {
                                HStack(spacing: 8) {
                                    ProgressView()
                                        .scaleEffect(0.8)
                                    Text("Setting up secure connection…")
                                        .font(.caption)
                                        .foregroundColor(LadonTheme.textSecondary)
                                }
                            } else {
                                Label("Tor is not connected — messages are held back", systemImage: "exclamationmark.triangle.fill")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.coralInk)
                            }
                        }
                    }
                    .padding(16)
                }

                // How It Works
                GlassSection(header: "How It Works") {
                    VStack(alignment: .leading, spacing: 12) {
                        Label {
                            Text("What is Tor?")
                        } icon: {
                            Image(systemName: "globe.europe.africa")
                                .foregroundColor(LadonTheme.textPrimary)
                        }
                        .font(.headline)

                        Text("Tor (The Onion Router) provides network-level anonymity by routing your traffic through multiple encrypted relays.")
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)

                        CardDivider().padding(.vertical, 2)

                        HStack(spacing: 8) {
                            VStack(spacing: 4) {
                                routeIcon("iphone", relay: false)
                                Text("You").font(.caption2).lineLimit(1).minimumScaleFactor(0.7)
                            }
                            Image(systemName: "arrow.right").font(.caption).foregroundColor(LadonTheme.textSecondary)
                            VStack(spacing: 4) {
                                routeIcon("server.rack", relay: true)
                                Text("Guard").font(.caption2).lineLimit(1).minimumScaleFactor(0.7)
                            }
                            Image(systemName: "arrow.right").font(.caption).foregroundColor(LadonTheme.textSecondary)
                            VStack(spacing: 4) {
                                routeIcon("server.rack", relay: true)
                                Text("Middle").font(.caption2).lineLimit(1).minimumScaleFactor(0.7)
                            }
                            Image(systemName: "arrow.right").font(.caption).foregroundColor(LadonTheme.textSecondary)
                            VStack(spacing: 4) {
                                routeIcon("server.rack", relay: true)
                                Text("Exit").font(.caption2).lineLimit(1).minimumScaleFactor(0.7)
                            }
                            Image(systemName: "arrow.right").font(.caption).foregroundColor(LadonTheme.textSecondary)
                            VStack(spacing: 4) {
                                Image(systemName: "network").font(.title3)
                                Text("Server").font(.caption2).lineLimit(1).minimumScaleFactor(0.7)
                            }
                        }
                        .frame(maxWidth: .infinity)

                        CardDivider().padding(.vertical, 2)

                        VStack(alignment: .leading, spacing: 8) {
                            Label("ISP cannot see destination", systemImage: "eye.slash.fill")
                                .font(.caption).foregroundColor(LadonTheme.greenInk)
                            Label("Server cannot see your IP", systemImage: "network.slash")
                                .font(.caption).foregroundColor(LadonTheme.greenInk)
                            Label("No single relay knows both endpoints", systemImage: "lock.shield.fill")
                                .font(.caption).foregroundColor(LadonTheme.greenInk)
                        }
                    }
                    .padding(16)
                }

                // Trade-offs
                GlassSection(header: "Trade-offs") {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Slower connection speed", systemImage: "tortoise.fill")
                            .font(.caption).foregroundColor(LadonTheme.coralInk)
                        Label("Higher battery usage", systemImage: "battery.25")
                            .font(.caption).foregroundColor(LadonTheme.coralInk)
                        Label("Some networks may block Tor", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundColor(LadonTheme.coralInk)
                    }
                    .padding(16)
                }

                // Security Benefits
                GlassSection(header: "Security Benefits") {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("ISP cannot monitor traffic", systemImage: "eye.slash.fill")
                            .font(.caption).foregroundColor(LadonTheme.greenInk)
                        Label("Prevents traffic analysis", systemImage: "chart.line.downtrend.xyaxis")
                            .font(.caption).foregroundColor(LadonTheme.greenInk)
                        Label("Censorship circumvention", systemImage: "lock.open.fill")
                            .font(.caption).foregroundColor(LadonTheme.greenInk)
                        Label("Location privacy", systemImage: "location.slash.fill")
                            .font(.caption).foregroundColor(LadonTheme.greenInk)
                    }
                    .padding(16)
                }

            }
            .padding(.horizontal, 14)
            .padding(.top, 16)
            .padding(.bottom, 32)
        }
        }
        .navigationTitle("Tor Network")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
        .tint(LadonTheme.brandGreen)
    }
}


#Preview {
    NavigationStack {
        TorSettingsView()
    }
}
