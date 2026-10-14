import SwiftUI

/// Manages in-app language selection. Stores preference in UserDefaults.
/// Language is NEVER sent to any server or included in network requests.
@MainActor
final class LanguageManager: ObservableObject {
    static let shared = LanguageManager()
    
    /// Available languages — add new entries here to support more languages
    static let supportedLanguages: [(code: String, name: String, flag: String)] = [
        ("en", "English", "🇬🇧"),
        ("de", "Deutsch", "🇩🇪"),
    ]
    
    // nonisolated so localized(_:) can read it off the main actor (immutable).
    nonisolated private static let storageKey = "app.ladon.selectedLanguage"
    
    @Published var selectedLanguage: String {
        didSet {
            UserDefaults.standard.set(selectedLanguage, forKey: Self.storageKey)
        }
    }
    
    var locale: Locale {
        Locale(identifier: selectedLanguage)
    }

    /// Localize `key` to the IN-APP selected language — NOT the device locale.
    /// Needed for strings shown OUTSIDE SwiftUI's `.environment(\.locale)`:
    /// the system Face ID prompt (`LAContext.localizedReason`), LAContext button
    /// titles, and programmatic error strings assigned to `String` properties.
    /// Reads the persisted code directly so it is safe to call off the main actor.
    nonisolated static func localized(_ key: String) -> String {
        let code = UserDefaults.standard.string(forKey: Self.storageKey) ?? "en"
        guard let path = Bundle.main.path(forResource: code, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return key }
        return bundle.localizedString(forKey: key, value: key, table: nil)
    }

    private init() {
        self.selectedLanguage = UserDefaults.standard.string(forKey: Self.storageKey) ?? "en"
    }
}
