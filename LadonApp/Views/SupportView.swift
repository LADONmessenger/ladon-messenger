// SupportView.swift — Settings → Info → "Leave a tip".
// A voluntary one-time tip through Apple's In-App Purchase (consumables).
// A tip unlocks nothing and no server of ours is involved: nothing is sent
// to a relay, nothing is stored, no receipt is checked.
//
// The App Store is contacted only after the user taps "Show amounts":
// StoreKit talks to Apple directly, outside Tor, so the screen says so first
// and the app never reaches Apple on its own.

import SwiftUI
import StoreKit

/// Product IDs of the tip tiers in App Store Connect (consumables), smallest first.
enum TipJar {
    static let amounts = [5, 10, 15, 20, 25, 50, 100, 500, 1000]
    static let productIDs = amounts.map { "app.ladon.messenger.tip.\($0)" }
}

struct SupportView: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    private var isDark: Bool { AppearanceManager.isDarkStored }

    private enum Phase: Equatable {
        case idle, loading, loaded, failed, thanks
    }

    @State private var phase: Phase = .idle
    @State private var products: [Product] = []
    @State private var purchasing: String?

    var body: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 22) {
                GlassSection(header: "Leave a tip") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("LADON messenger is free. A tip helps pay for the servers. It is voluntary, one-time, and unlocks nothing.")
                            .font(isDark ? .body : .manrope(15, .medium))
                            .foregroundColor(LadonTheme.textPrimary)
                        Text("Payment is handled by Apple. To show the amounts, the app contacts the App Store directly, not through Tor. Apple then sees that this device opened the tip screen.")
                            .font(isDark ? .subheadline : .manrope(13.5, relativeTo: .subheadline))
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
                }

                GlassSection(header: "Amount") {
                    content
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 16)
        }
        }
        .navigationTitle("Leave a tip")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
    }

    @ViewBuilder private var content: some View {
        switch phase {
        case .idle:
            rowButton("Show amounts") { Task { await load() } }
        case .loading:
            HStack { ProgressView(); Spacer() }
                .padding(.horizontal, 16).padding(.vertical, 13)
        case .failed:
            VStack(alignment: .leading, spacing: 0) {
                Text("The App Store could not be reached.")
                    .font(.caption)
                    .foregroundColor(LadonTheme.textSecondary)
                    .padding(.horizontal, 16).padding(.top, 13)
                rowButton("Try again") { Task { await load() } }
            }
        case .thanks:
            VStack(alignment: .leading, spacing: 6) {
                Text("Thank you.")
                    .font(isDark ? .headline : .manrope(17, .extrabold, relativeTo: .headline))
                    .foregroundColor(LadonTheme.textPrimary)
                Text("Your tip helps keep the servers running.")
                    .font(isDark ? .subheadline : .manrope(15, relativeTo: .subheadline))
                    .foregroundColor(LadonTheme.textSecondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
        case .loaded:
            VStack(spacing: 0) {
                ForEach(Array(products.enumerated()), id: \.element.id) { idx, product in
                    Button { Task { await buy(product) } } label: {
                        HStack {
                            Text(verbatim: product.displayName)
                                .font(isDark ? .body : .manrope(15.5, .bold))
                                .foregroundColor(LadonTheme.textPrimary)
                            Spacer()
                            if purchasing == product.id {
                                ProgressView()
                            } else {
                                Text(verbatim: product.displayPrice)
                                    .font(.jbMono(13, relativeTo: .body))
                                    .foregroundColor(LadonTheme.textPrimary)
                            }
                        }
                        .padding(.horizontal, 16).padding(.vertical, 13)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(purchasing != nil)
                    if idx < products.count - 1 { CardDivider() }
                }
            }
        }
    }

    private func rowButton(_ title: LocalizedStringKey, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(title)
                    .font(isDark ? .body : .manrope(15.5, .bold))
                    .foregroundColor(LadonTheme.textPrimary)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(LadonTheme.inkMuted)
            }
            .padding(.horizontal, 16).padding(.vertical, 13)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func load() async {
        phase = .loading
        // A tip interrupted earlier (e.g. waiting for Ask to Buy) is finished
        // here; there is nothing to deliver, so finishing is all it needs.
        for await result in Transaction.unfinished {
            if case .verified(let transaction) = result { await transaction.finish() }
        }
        do {
            let loaded = try await Product.products(for: TipJar.productIDs)
            products = loaded.sorted { $0.price < $1.price }
            phase = products.isEmpty ? .failed : .loaded
        } catch {
            phase = .failed
        }
    }

    private func buy(_ product: Product) async {
        purchasing = product.id
        defer { purchasing = nil }
        guard let result = try? await product.purchase() else { return }
        if case .success(.verified(let transaction)) = result {
            await transaction.finish()
            phase = .thanks
        }
        // .pending (Ask to Buy), .userCancelled, unverified: nothing to do.
    }
}
