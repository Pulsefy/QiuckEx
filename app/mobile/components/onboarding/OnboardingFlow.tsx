import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Dimensions,
  Animated,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';

import { useTheme } from '../../src/theme/ThemeContext';

const { width } = Dimensions.get('window');

interface OnboardingStep {
  id: string;
  title: string;
  subtitle: string;
  content: React.ReactNode;
  action?: string;
}

interface OnboardingFlowProps {
  onComplete?: () => void;
  onSkip?: () => void;
}

export default function OnboardingFlow({ onComplete, onSkip }: OnboardingFlowProps) {
  const router = useRouter();
  const { theme } = useTheme();

  const [currentStep, setCurrentStep] = useState(0);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [fadeAnim] = useState(new Animated.Value(1));

  const steps: OnboardingStep[] = [
    {
      id: 'welcome',
      title: 'Welcome to QuickEx',
      subtitle: 'Fast, privacy-focused payments on Stellar',
      content: (
        <View style={styles.welcomeContent}>
          <View
            style={[
              styles.iconContainer,
              { backgroundColor: theme.inputBg, borderColor: theme.border },
            ]}
          >
            <Ionicons name="wallet-outline" size={80} color={theme.textPrimary} />
          </View>
          <Text style={[styles.description, { color: theme.textSecondary }]}> 
            Send and receive USDC, XLM, and any Stellar asset instantly with your self-custody wallet.
          </Text>
        </View>
      ),
      action: 'Get Started',
    },
    {
      id: 'wallet-basics',
      title: 'Your Digital Wallet',
      subtitle: 'Understanding self-custody',
      content: (
        <View style={styles.educationContent}>
          <View style={styles.visualContainer}>
            <View style={styles.walletVisual}>
              <Ionicons name="lock-closed" size={40} color={theme.status.success} />
              <Text style={[styles.visualText, { color: theme.textPrimary }]}>Your Keys</Text>
            </View>
            <Ionicons name="arrow-forward" size={24} color={theme.textMuted} />
            <View style={styles.walletVisual}>
              <Ionicons name="globe-outline" size={40} color={theme.status.info} />
              <Text style={[styles.visualText, { color: theme.textPrimary }]}>Stellar Network</Text>
            </View>
          </View>
          <Text style={[styles.description, { color: theme.textSecondary }]}> 
            • You control your private keys{"\n"}
            • No third-party custody{"\n"}
            • Transactions are irreversible{"\n"}
            • Always verify recipient addresses
          </Text>
        </View>
      ),
      action: 'I Understand',
    },
    {
      id: 'signing',
      title: 'Transaction Signing',
      subtitle: 'How payments work',
      content: (
        <View style={styles.educationContent}>
          <View style={styles.signingFlow}>
            <View
              style={[
                styles.stepBox,
                {
                  backgroundColor: theme.surface,
                  borderColor: theme.border,
                },
              ]}
            >
              <Ionicons name="create-outline" size={30} color={theme.textPrimary} />
              <Text style={[styles.stepText, { color: theme.textPrimary }]}>1. You initiate payment</Text>
            </View>
            <Ionicons name="chevron-down" size={20} color={theme.textMuted} />
            <View
              style={[
                styles.stepBox,
                {
                  backgroundColor: theme.surface,
                  borderColor: theme.border,
                },
              ]}
            >
              <Ionicons name="key-outline" size={30} color={theme.status.warning} />
              <Text style={[styles.stepText, { color: theme.textPrimary }]}>2. You sign with private key</Text>
            </View>
            <Ionicons name="chevron-down" size={20} color={theme.textMuted} />
            <View
              style={[
                styles.stepBox,
                {
                  backgroundColor: theme.surface,
                  borderColor: theme.border,
                },
              ]}
            >
              <Ionicons name="checkmark-circle" size={30} color={theme.status.success} />
              <Text style={[styles.stepText, { color: theme.textPrimary }]}>3. Network verifies and executes</Text>
            </View>
          </View>
          <Text style={[styles.description, { color: theme.textSecondary }]}> 
            Each transaction requires your digital signature. Never share your private key or recovery phrase.
          </Text>
        </View>
      ),
      action: 'Got It',
    },
    {
      id: 'demo-choice',
      title: 'Choose Your Experience',
      subtitle: 'Try demo mode or jump right in',
      content: (
        <View style={styles.choiceContent}>
          <TouchableOpacity
            style={[
              styles.choiceCard,
              {
                backgroundColor: isDemoMode ? theme.chipActiveBg : theme.surface,
                borderColor: isDemoMode ? theme.chipActiveBg : theme.border,
              },
            ]}
            onPress={() => setIsDemoMode(true)}
          >
            <Ionicons
              name="school-outline"
              size={40}
              color={isDemoMode ? theme.chipActiveText : theme.status.info}
            />
            <Text
              style={[
                styles.choiceTitle,
                { color: isDemoMode ? theme.chipActiveText : theme.textPrimary },
              ]}
            >
              Demo Mode
            </Text>
            <Text
              style={[
                styles.choiceDescription,
                { color: isDemoMode ? theme.chipActiveText : theme.textSecondary },
              ]}
            >
              Practice with testnet funds{"\n"}
              No real money required{"\n"}
              Learn risk-free
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[
              styles.choiceCard,
              {
                backgroundColor: !isDemoMode ? theme.chipActiveBg : theme.surface,
                borderColor: !isDemoMode ? theme.chipActiveBg : theme.border,
              },
            ]}
            onPress={() => setIsDemoMode(false)}
          >
            <Ionicons
              name="rocket-outline"
              size={40}
              color={!isDemoMode ? theme.chipActiveText : theme.status.success}
            />
            <Text
              style={[
                styles.choiceTitle,
                { color: !isDemoMode ? theme.chipActiveText : theme.textPrimary },
              ]}
            >
              Real Mode
            </Text>
            <Text
              style={[
                styles.choiceDescription,
                { color: !isDemoMode ? theme.chipActiveText : theme.textSecondary },
              ]}
            >
              Use actual funds{"\n"}
              Live transactions{"\n"}
              Full functionality
            </Text>
          </TouchableOpacity>
        </View>
      ),
      action: isDemoMode ? 'Start Demo' : 'Connect Real Wallet',
    },
  ];

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      Animated.timing(fadeAnim, {
        toValue: 0,
        duration: 200,
        useNativeDriver: true,
      }).start(() => {
        setCurrentStep(currentStep + 1);
        Animated.timing(fadeAnim, {
          toValue: 1,
          duration: 200,
          useNativeDriver: true,
        }).start();
      });
    } else {
      handleComplete();
    }
  };

  const handleComplete = () => {
    trackOnboardingEvent('onboarding_completed', {
      demo_mode: isDemoMode,
      steps_completed: currentStep + 1,
    });

    if (onComplete) {
      onComplete();
    } else {
      router.push({
        pathname: '/wallet-connect',
        params: { demo: isDemoMode.toString() },
      });
    }
  };

  const handleSkip = () => {
    trackOnboardingEvent('onboarding_skipped', {
      step: currentStep,
      steps_completed: currentStep,
    });

    if (onSkip) {
      onSkip();
    } else {
      router.replace('/');
    }
  };

  const trackOnboardingEvent = (eventName: string, params: Record<string, unknown>) => {
    console.log('Analytics Event:', eventName, params);
  };

  const currentStepData = steps[currentStep];
  const progress = ((currentStep + 1) / steps.length) * 100;

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}> 
      <View style={styles.header}>
        <TouchableOpacity onPress={handleSkip} style={styles.skipButton}>
          <Text style={[styles.skipText, { color: theme.textMuted }]}>Skip</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.progressContainer}>
        <View style={[styles.progressBar, { backgroundColor: theme.border }]}> 
          <View style={[styles.progressFill, { width: `${progress}%`, backgroundColor: theme.primary }]} />
        </View>
        <Text style={[styles.progressText, { color: theme.textMuted }]}>
          Step {currentStep + 1} of {steps.length}
        </Text>
      </View>

      <Animated.View style={[styles.content, { opacity: fadeAnim }]}> 
        <Text style={[styles.title, { color: theme.textPrimary }]}>{currentStepData.title}</Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>{currentStepData.subtitle}</Text>

        {currentStepData.content}
      </Animated.View>

      <View style={styles.footer}>
        <View style={styles.dotsContainer}>
          {steps.map((_, index) => (
            <View
              key={index}
              style={[
                styles.dot,
                {
                  backgroundColor: index === currentStep ? theme.primary : theme.border,
                  width: index === currentStep ? 24 : 8,
                },
              ]}
            />
          ))}
        </View>

        <TouchableOpacity
          style={[styles.nextButton, { backgroundColor: theme.buttonPrimaryBg }]}
          onPress={handleNext}
        >
          <Text style={[styles.nextButtonText, { color: theme.buttonPrimaryText }]}> 
            {currentStepData.action || 'Next'}
          </Text>
          <Ionicons name="arrow-forward" size={20} color={theme.buttonPrimaryText} />
        </TouchableOpacity>

        {currentStep > 0 && (
          <TouchableOpacity
            style={styles.backButton}
            onPress={() => setCurrentStep(currentStep - 1)}
          >
            <Text style={[styles.backButtonText, { color: theme.textMuted }]}>Back</Text>
          </TouchableOpacity>
        )}
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    paddingHorizontal: 24,
    paddingTop: 12,
  },
  skipButton: {
    padding: 8,
  },
  skipText: {
    fontSize: 16,
    fontWeight: '500',
  },
  progressContainer: {
    paddingHorizontal: 24,
    marginTop: 20,
    marginBottom: 32,
  },
  progressBar: {
    height: 4,
    borderRadius: 2,
    marginBottom: 8,
  },
  progressFill: {
    height: '100%',
    borderRadius: 2,
  },
  progressText: {
    fontSize: 14,
    textAlign: 'center',
  },
  content: {
    flex: 1,
    paddingHorizontal: 24,
    justifyContent: 'center',
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 18,
    textAlign: 'center',
    marginBottom: 40,
  },
  welcomeContent: {
    alignItems: 'center',
  },
  iconContainer: {
    width: 120,
    height: 120,
    borderRadius: 60,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 32,
    borderWidth: 1,
  },
  educationContent: {
    alignItems: 'center',
  },
  visualContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 32,
    width: Math.min(width - 48, 420),
  },
  walletVisual: {
    alignItems: 'center',
    padding: 16,
  },
  visualText: {
    fontSize: 14,
    fontWeight: '600',
    marginTop: 8,
  },
  signingFlow: {
    width: '100%',
    marginBottom: 32,
  },
  stepBox: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    borderRadius: 12,
    marginBottom: 12,
    borderWidth: 1,
  },
  stepText: {
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 12,
    flexShrink: 1,
  },
  description: {
    fontSize: 16,
    lineHeight: 24,
    textAlign: 'center',
  },
  choiceContent: {
    gap: 16,
  },
  choiceCard: {
    borderRadius: 16,
    padding: 24,
    borderWidth: 2,
    alignItems: 'center',
  },
  choiceTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginTop: 12,
    marginBottom: 8,
  },
  choiceDescription: {
    fontSize: 14,
    lineHeight: 20,
    textAlign: 'center',
  },
  footer: {
    paddingHorizontal: 24,
    paddingBottom: 32,
    alignItems: 'center',
  },
  dotsContainer: {
    flexDirection: 'row',
    marginBottom: 24,
  },
  dot: {
    height: 8,
    borderRadius: 4,
    marginHorizontal: 4,
  },
  nextButton: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: '100%',
    justifyContent: 'center',
    gap: 8,
  },
  nextButtonText: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  backButton: {
    marginTop: 12,
    padding: 8,
  },
  backButtonText: {
    fontSize: 16,
  },
});
