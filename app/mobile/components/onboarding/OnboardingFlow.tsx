import React, { useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Dimensions, Animated } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';

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
          <View style={styles.iconContainer}>
            <Ionicons name="wallet-outline" size={80} color="#000" />
          </View>
          <Text style={styles.description}>
            Send and receive USDC, XLM, and any Stellar asset instantly with your self-custody wallet.
          </Text>
        </View>
      ),
      action: 'Get Started'
    },
    {
      id: 'wallet-basics',
      title: 'Your Digital Wallet',
      subtitle: 'Understanding self-custody',
      content: (
        <View style={styles.educationContent}>
          <View style={styles.visualContainer}>
            <View style={styles.walletVisual}>
              <Ionicons name="lock-closed" size={40} color="#10B981" />
              <Text style={styles.visualText}>Your Keys</Text>
            </View>
            <Ionicons name="arrow-forward" size={24} color="#666" />
            <View style={styles.walletVisual}>
              <Ionicons name="globe-outline" size={40} color="#2563EB" />
              <Text style={styles.visualText}>Stellar Network</Text>
            </View>
          </View>
          <Text style={styles.description}>
            • You control your private keys{'\n'}
            • No third-party custody{'\n'}
            • Transactions are irreversible{'\n'}
            • Always verify recipient addresses
          </Text>
        </View>
      ),
      action: 'I Understand'
    },
    {
      id: 'signing',
      title: 'Transaction Signing',
      subtitle: 'How payments work',
      content: (
        <View style={styles.educationContent}>
          <View style={styles.signingFlow}>
            <View style={styles.stepBox}>
              <Ionicons name="create-outline" size={30} color="#000" />
              <Text style={styles.stepText}>1. You initiate payment</Text>
            </View>
            <Ionicons name="chevron-down" size={20} color="#666" />
            <View style={styles.stepBox}>
              <Ionicons name="key-outline" size={30} color="#F59E0B" />
              <Text style={styles.stepText}>2. You sign with private key</Text>
            </View>
            <Ionicons name="chevron-down" size={20} color="#666" />
            <View style={styles.stepBox}>
              <Ionicons name="checkmark-circle" size={30} color="#10B981" />
              <Text style={styles.stepText}>3. Network verifies & executes</Text>
            </View>
          </View>
          <Text style={styles.description}>
            Each transaction requires your digital signature. Never share your private key or recovery phrase.
          </Text>
        </View>
      ),
      action: 'Got It'
    },
    {
      id: 'demo-choice',
      title: 'Choose Your Experience',
      subtitle: 'Try demo mode or jump right in',
      content: (
        <View style={styles.choiceContent}>
          <TouchableOpacity
            style={[styles.choiceCard, isDemoMode && styles.selectedCard]}
            onPress={() => setIsDemoMode(true)}
          >
            <Ionicons name="school-outline" size={40} color="#2563EB" />
            <Text style={styles.choiceTitle}>Demo Mode</Text>
            <Text style={styles.choiceDescription}>
              Practice with testnet funds{'\n'}
              No real money required{'\n'}
              Learn risk-free
            </Text>
          </TouchableOpacity>
          
          <TouchableOpacity
            style={[styles.choiceCard, !isDemoMode && styles.selectedCard]}
            onPress={() => setIsDemoMode(false)}
          >
            <Ionicons name="rocket-outline" size={40} color="#10B981" />
            <Text style={styles.choiceTitle}>Real Mode</Text>
            <Text style={styles.choiceDescription}>
              Use actual funds{'\n'}
              Live transactions{'\n'}
              Full functionality
            </Text>
          </TouchableOpacity>
        </View>
      ),
      action: isDemoMode ? 'Start Demo' : 'Connect Real Wallet'
    }
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
    // Track onboarding completion
    trackOnboardingEvent('onboarding_completed', {
      demo_mode: isDemoMode,
      steps_completed: currentStep + 1,
    });
    
    if (onComplete) {
      onComplete();
    } else {
      // Navigate to wallet connect with demo flag
      router.push({
        pathname: '/wallet-connect',
        params: { demo: isDemoMode.toString() }
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

  const trackOnboardingEvent = (eventName: string, params: Record<string, any>) => {
    // Analytics tracking - will be implemented separately
    console.log('Analytics Event:', eventName, params);
  };

  const currentStepData = steps[currentStep];
  const progress = ((currentStep + 1) / steps.length) * 100;

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={handleSkip} style={styles.skipButton}>
          <Text style={styles.skipText}>Skip</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.progressContainer}>
        <View style={styles.progressBar}>
          <View style={[styles.progressFill, { width: `${progress}%` }]} />
        </View>
        <Text style={styles.progressText}>
          Step {currentStep + 1} of {steps.length}
        </Text>
      </View>

      <Animated.View style={[styles.content, { opacity: fadeAnim }]}>
        <Text style={styles.title}>{currentStepData.title}</Text>
        <Text style={styles.subtitle}>{currentStepData.subtitle}</Text>
        
        {currentStepData.content}
      </Animated.View>

      <View style={styles.footer}>
        <View style={styles.dotsContainer}>
          {steps.map((_, index) => (
            <View
              key={index}
              style={[
                styles.dot,
                index === currentStep ? styles.activeDot : styles.inactiveDot
              ]}
            />
          ))}
        </View>

        <TouchableOpacity style={styles.nextButton} onPress={handleNext}>
          <Text style={styles.nextButtonText}>
            {currentStepData.action || 'Next'}
          </Text>
          <Ionicons name="arrow-forward" size={20} color="#fff" />
        </TouchableOpacity>

        {currentStep > 0 && (
          <TouchableOpacity
            style={styles.backButton}
            onPress={() => setCurrentStep(currentStep - 1)}
          >
            <Text style={styles.backButtonText}>Back</Text>
          </TouchableOpacity>
        )}
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
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
    color: '#666',
    fontWeight: '500',
  },
  progressContainer: {
    paddingHorizontal: 24,
    marginTop: 20,
    marginBottom: 32,
  },
  progressBar: {
    height: 4,
    backgroundColor: '#E5E7EB',
    borderRadius: 2,
    marginBottom: 8,
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#000',
    borderRadius: 2,
  },
  progressText: {
    fontSize: 14,
    color: '#666',
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
    color: '#000',
    textAlign: 'center',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 18,
    color: '#666',
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
    backgroundColor: '#F5F5F5',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 32,
  },
  educationContent: {
    alignItems: 'center',
  },
  visualContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 32,
  },
  walletVisual: {
    alignItems: 'center',
    padding: 16,
  },
  visualText: {
    fontSize: 14,
    fontWeight: '600',
    marginTop: 8,
    color: '#333',
  },
  signingFlow: {
    width: '100%',
    marginBottom: 32,
  },
  stepBox: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#F9FAFB',
    padding: 16,
    borderRadius: 12,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  stepText: {
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 12,
    color: '#333',
  },
  description: {
    fontSize: 16,
    lineHeight: 24,
    color: '#555',
    textAlign: 'center',
  },
  choiceContent: {
    gap: 16,
  },
  choiceCard: {
    backgroundColor: '#F9FAFB',
    borderRadius: 16,
    padding: 24,
    borderWidth: 2,
    borderColor: '#E5E7EB',
    alignItems: 'center',
  },
  selectedCard: {
    borderColor: '#000',
    backgroundColor: '#000',
  },
  choiceTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginTop: 12,
    marginBottom: 8,
    color: '#333',
  },
  choiceDescription: {
    fontSize: 14,
    lineHeight: 20,
    color: '#666',
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
    width: 8,
    height: 8,
    borderRadius: 4,
    marginHorizontal: 4,
  },
  activeDot: {
    backgroundColor: '#000',
    width: 24,
  },
  inactiveDot: {
    backgroundColor: '#D1D5DB',
  },
  nextButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#000',
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: '100%',
    justifyContent: 'center',
    gap: 8,
  },
  nextButtonText: {
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  backButton: {
    marginTop: 12,
    padding: 8,
  },
  backButtonText: {
    color: '#666',
    fontSize: 16,
  },
});
