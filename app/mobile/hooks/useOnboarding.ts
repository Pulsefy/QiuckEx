import { useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

const ONBOARDING_STORAGE_KEY = 'quickex_onboarding_completed';
const ANALYTICS_STORAGE_KEY = 'quickex_onboarding_events';

interface OnboardingEvent {
  event_name: string;
  timestamp: number;
  step?: number;
  demo_mode?: boolean;
  steps_completed?: number;
  session_id: string;
}

export function useOnboarding() {
  const [hasCompletedOnboarding, setHasCompletedOnboarding] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    checkOnboardingStatus();
  }, []);

  const checkOnboardingStatus = async () => {
    try {
      const completed = await AsyncStorage.getItem(ONBOARDING_STORAGE_KEY);
      setHasCompletedOnboarding(completed === 'true');
    } catch (error) {
      console.error('Error checking onboarding status:', error);
      setHasCompletedOnboarding(false);
    } finally {
      setIsLoading(false);
    }
  };

  const markOnboardingComplete = async () => {
    try {
      await AsyncStorage.setItem(ONBOARDING_STORAGE_KEY, 'true');
      setHasCompletedOnboarding(true);
    } catch (error) {
      console.error('Error marking onboarding complete:', error);
    }
  };

  const resetOnboarding = async () => {
    try {
      await AsyncStorage.removeItem(ONBOARDING_STORAGE_KEY);
      await AsyncStorage.removeItem(ANALYTICS_STORAGE_KEY);
      setHasCompletedOnboarding(false);
    } catch (error) {
      console.error('Error resetting onboarding:', error);
    }
  };

  const trackOnboardingEvent = async (eventName: string, params: Record<string, any>) => {
    try {
      const sessionId = await getOrCreateSessionId();
      const event: OnboardingEvent = {
        event_name: eventName,
        timestamp: Date.now(),
        session_id: sessionId,
        ...params,
      };

      const existingEvents = await AsyncStorage.getItem(ANALYTICS_STORAGE_KEY);
      const events: OnboardingEvent[] = existingEvents ? JSON.parse(existingEvents) : [];
      events.push(event);

      await AsyncStorage.setItem(ANALYTICS_STORAGE_KEY, JSON.stringify(events));

      // Log to console for now - in production, this would send to analytics service
      console.log('Onboarding Analytics:', event);

      // In a real implementation, you would also send this to your analytics backend
      // await sendToAnalytics(event);
    } catch (error) {
      console.error('Error tracking onboarding event:', error);
    }
  };

  const getOnboardingEvents = async (): Promise<OnboardingEvent[]> => {
    try {
      const events = await AsyncStorage.getItem(ANALYTICS_STORAGE_KEY);
      return events ? JSON.parse(events) : [];
    } catch (error) {
      console.error('Error getting onboarding events:', error);
      return [];
    }
  };

  const getOrCreateSessionId = async (): Promise<string> => {
    const SESSION_ID_KEY = 'quickex_session_id';
    try {
      let sessionId = await AsyncStorage.getItem(SESSION_ID_KEY);
      if (!sessionId) {
        sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        await AsyncStorage.setItem(SESSION_ID_KEY, sessionId);
      }
      return sessionId;
    } catch (error) {
      console.error('Error creating session ID:', error);
      return `fallback_session_${Date.now()}`;
    }
  };

  const getOnboardingFunnelData = async () => {
    try {
      const events = await getOnboardingEvents();
      const funnelData = {
        started: events.filter(e => e.event_name === 'onboarding_started').length,
        completed: events.filter(e => e.event_name === 'onboarding_completed').length,
        skipped: events.filter(e => e.event_name === 'onboarding_skipped').length,
        demo_mode_users: events.filter(e => e.event_name === 'onboarding_completed' && e.demo_mode).length,
        real_mode_users: events.filter(e => e.event_name === 'onboarding_completed' && !e.demo_mode).length,
        average_steps_completed: 0,
        drop_off_points: [] as number[],
      };

      // Calculate average steps completed
      const completedEvents = events.filter(e => e.event_name === 'onboarding_completed');
      if (completedEvents.length > 0) {
        const totalSteps = completedEvents.reduce((sum, e) => sum + (e.steps_completed || 0), 0);
        funnelData.average_steps_completed = totalSteps / completedEvents.length;
      }

      // Calculate drop-off points
      const skippedEvents = events.filter(e => e.event_name === 'onboarding_skipped');
      funnelData.drop_off_points = skippedEvents.map(e => e.step || 0);

      return funnelData;
    } catch (error) {
      console.error('Error getting funnel data:', error);
      return null;
    }
  };

  return {
    hasCompletedOnboarding,
    isLoading,
    markOnboardingComplete,
    resetOnboarding,
    trackOnboardingEvent,
    getOnboardingEvents,
    getOnboardingFunnelData,
  };
}
