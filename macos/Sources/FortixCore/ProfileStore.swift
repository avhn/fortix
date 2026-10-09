import Foundation

/// ProfileStore keeps configuration authority in the helper instead of writing root-owned files.
public actor ProfileStore {
  /// Client owns correlation, framing, and transport failure handling.
  private let client: HelperClient

  /// Creates a helper-backed store without connecting or loading local configuration copies.
  public init(client: HelperClient) { self.client = client }

  /// List returns lightweight stored IDs and phases; a missing payload is a protocol error.
  public func list() async throws -> [ProfileState] {
    let result = try await client.call(HelperRequest(op: "profile.list"))
    guard let data = result.data else { throw CoreError.invalidMessage }
    let entries: [ProfileState] = try data.decode([ProfileState].self)
    guard entries.allSatisfy({ VPNProfile.validID($0.profile) }),
      Set(entries.map(\.profile)).count == entries.count
    else { throw CoreError.invalidMessage }
    return entries
  }

  /// Get loads one exact identity; mismatched helper responses cannot select another credential key.
  public func get(_ id: String) async throws -> VPNProfile {
    guard VPNProfile.validID(id) else { throw CoreError.invalidProfile }
    let result = try await client.call(HelperRequest(op: "profile.get", profile: id))
    guard let data = result.data else { throw CoreError.invalidMessage }
    let profile = try VPNProfile.decode(data)
    guard profile.id == id else { throw CoreError.invalidMessage }
    return profile
  }

  /// Put sends a secret-free profile object; active-profile and trust rules remain helper-enforced.
  public func put(_ profile: VPNProfile) async throws {
    try profile.validate()
    _ = try await client.call(
      HelperRequest(op: "profile.put", profileJSON: JSONValue.make(profile)))
  }

  /// Delete asks the helper to remove one idle profile; it never directly touches privileged storage.
  public func delete(_ id: String) async throws {
    guard VPNProfile.validID(id) else { throw CoreError.invalidProfile }
    _ = try await client.call(HelperRequest(op: "profile.delete", profile: id))
  }

  /// All loads configurations sequentially to avoid unbounded socket requests during profile refresh.
  public func all() async throws -> [VPNProfile] {
    var profiles: [VPNProfile] = []
    for entry in try await list() { profiles.append(try await get(entry.profile)) }
    return profiles
  }
}
