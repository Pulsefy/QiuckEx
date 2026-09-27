import React, { useState } from "react";
import { View, Text, TouchableOpacity, StyleSheet } from "react-native";
import { useNetworkGuardContext } from "../../contexts/NetworkGuardContext";
import {
  NetworkMismatchGuard,
  NetworkMismatchGuardButton,
} from "./NetworkMismatchGuard";
import { WalletSwitchHelpModal } from "./WalletSwitchHelpModal";

/**
 * INTEGRATION EXAMPLE: How to use Network Guards in your screens
 *
 * This component demonstrates:
 * 1. Wrapping transactional actions with NetworkMismatchGuard
 * 2. Handling blocked actions
 * 3. Showing help modal when needed
 */
export function TransactionActionsWithGuards() {
  const { guard } = useNetworkGuardContext();
  const [showHelpModal, setShowHelpModal] = useState(false);

  // Handler for Pay action
  const handlePay = () => {
    if (guard.isMismatched) {
      setShowHelpModal(true);
      return;
    }
    // Perform actual pay operation
    console.log("Processing payment...");
  };

  // Handler for Refund action
  const handleRefund = () => {
    if (guard.isMismatched) {
      setShowHelpModal(true);
      return;
    }
    // Perform actual refund operation
    console.log("Processing refund...");
  };

  // Handler for Dispute action
  const handleDispute = () => {
    if (guard.isMismatched) {
      setShowHelpModal(true);
      return;
    }
    // Perform actual dispute operation
    console.log("Processing dispute...");
  };

  return (
    <View style={styles.container}>
      {/* Status indicator */}
      <View style={styles.statusSection}>
        <Text style={styles.statusLabel}>Network Status:</Text>
        <Text
          style={[
            styles.statusBadge,
            guard.isMismatched ? styles.statusError : styles.statusOk,
          ]}
        >
          {guard.isMismatched ? "BLOCKED" : "OK"}{" "}
          {guard.currentNetwork.toUpperCase()}
        </Text>
      </View>

      {/* Action buttons wrapped with guards */}
      <View style={styles.actionsSection}>
        <Text style={styles.sectionTitle}>Transaction Actions</Text>

        {/* Example 1: Wrapper guard on a custom button */}
        <NetworkMismatchGuard onBlocked={() => setShowHelpModal(true)}>
          <TouchableOpacity
            style={styles.actionButton}
            onPress={handlePay}
            disabled={guard.isMismatched}
          >
            <Text style={styles.buttonText}>💰 Pay Now</Text>
          </TouchableOpacity>
        </NetworkMismatchGuard>

        {/* Example 2: Button variant guard */}
        <NetworkMismatchGuardButton
          onBlocked={() => setShowHelpModal(true)}
          onPress={handleRefund}
          style={styles.actionButton}
        >
          🔄 Refund
        </NetworkMismatchGuardButton>

        {/* Example 3: Another wrapper guard */}
        <NetworkMismatchGuard onBlocked={() => setShowHelpModal(true)}>
          <TouchableOpacity
            style={styles.actionButton}
            onPress={handleDispute}
            disabled={guard.isMismatched}
          >
            <Text style={styles.buttonText}>⚖️ Dispute</Text>
          </TouchableOpacity>
        </NetworkMismatchGuard>
      </View>

      {/* Info section */}
      <View style={styles.infoSection}>
        <Text style={styles.infoTitle}>ℹ️ How Network Guards Work</Text>
        <Text style={styles.infoText}>
          • When your wallet is on {guard.expectedNetwork.toUpperCase()}: All
          actions work normally{"\n"}• When there's a mismatch: Actions are
          blocked with helpful warnings{"\n"}• Tap blocked actions to see
          wallet switching instructions
        </Text>
      </View>

      {/* Help modal */}
      <WalletSwitchHelpModal
        visible={showHelpModal}
        onClose={() => setShowHelpModal(false)}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingHorizontal: 16,
    paddingVertical: 20,
  },

  statusSection: {
    backgroundColor: "#F3F4F6",
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderRadius: 8,
    marginBottom: 24,
  },

  statusLabel: {
    fontSize: 12,
    color: "#6B7280",
    fontWeight: "500",
    marginBottom: 6,
  },

  statusBadge: {
    fontSize: 14,
    fontWeight: "700",
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
    overflow: "hidden",
    alignSelf: "flex-start",
  },

  statusOk: {
    backgroundColor: "#D1FAE5",
    color: "#065F46",
  },

  statusError: {
    backgroundColor: "#FEE2E2",
    color: "#DC2626",
  },

  actionsSection: {
    marginBottom: 24,
  },

  sectionTitle: {
    fontSize: 16,
    fontWeight: "700",
    color: "#1F2937",
    marginBottom: 12,
  },

  actionButton: {
    backgroundColor: "#3B82F6",
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    marginBottom: 10,
    justifyContent: "center",
    alignItems: "center",
  },

  buttonText: {
    color: "#FFFFFF",
    fontWeight: "600",
    fontSize: 14,
  },

  infoSection: {
    backgroundColor: "#DBEAFE",
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: "#0EA5E9",
  },

  infoTitle: {
    fontSize: 14,
    fontWeight: "700",
    color: "#0C4A6E",
    marginBottom: 8,
  },

  infoText: {
    fontSize: 12,
    color: "#164E63",
    lineHeight: 18,
  },
});
