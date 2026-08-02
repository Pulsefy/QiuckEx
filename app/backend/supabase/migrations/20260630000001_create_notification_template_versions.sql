-- Create notification template versioning system
-- This implements template versioning with active/draft states, allowing operators
-- to evolve templates without breaking historical records. Delivered notifications
-- link to the specific template version that was used.

-- ---------------------------------------------------------------------------
-- notification_templates
-- ---------------------------------------------------------------------------
-- Base template definition (one per event type)
CREATE TABLE IF NOT EXISTS notification_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL UNIQUE, -- Maps to NotificationEventType (e.g. 'payment.received')
  name TEXT NOT NULL, -- Human-readable name for the template
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  CONSTRAINT notification_templates_event_type_unique UNIQUE (event_type)
);

CREATE INDEX IF NOT EXISTS idx_notification_templates_event_type ON notification_templates(event_type);

COMMENT ON TABLE notification_templates IS 'Base template definitions, one per event type';

-- ---------------------------------------------------------------------------
-- notification_template_versions
-- ---------------------------------------------------------------------------
-- Versioned template content with active/draft states
CREATE TABLE IF NOT EXISTS notification_template_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id UUID NOT NULL REFERENCES notification_templates(id) ON DELETE CASCADE,
  version_number INT NOT NULL, -- Semantic-like version incrementing per template
  title TEXT NOT NULL, -- Template title with {{variables}}
  body TEXT NOT NULL, -- Template body with {{variables}}
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived')),
  change_notes TEXT, -- Description of changes in this version
  created_by TEXT NOT NULL, -- User/API that created this version
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Only one active version per template
  CONSTRAINT notification_template_versions_active_unique UNIQUE (template_id, status) 
    DEFERRABLE INITIALLY DEFERRED,
  -- Version numbers are unique per template
  CONSTRAINT notification_template_versions_version_unique UNIQUE (template_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_notification_template_versions_template_id ON notification_template_versions(template_id);
CREATE INDEX IF NOT EXISTS idx_notification_template_versions_status ON notification_template_versions(status);
CREATE INDEX IF NOT EXISTS idx_notification_template_versions_version_number ON notification_template_versions(version_number);

COMMENT ON TABLE notification_template_versions IS 'Versioned template content with lifecycle states (draft/active/archived)';

-- ---------------------------------------------------------------------------
-- Add template_version_id to notification_log
-- ---------------------------------------------------------------------------
-- Link delivered notifications to the template version that was used
ALTER TABLE notification_log
  ADD COLUMN IF NOT EXISTS template_version_id UUID REFERENCES notification_template_versions(id);

CREATE INDEX IF NOT EXISTS idx_notification_log_template_version_id ON notification_log(template_version_id);

COMMENT ON COLUMN notification_log.template_version_id IS 'The specific template version used to render this notification';

-- Auto-update updated_at for new tables
CREATE OR REPLACE FUNCTION update_notification_templates_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_notification_templates_updated_at
  BEFORE UPDATE ON notification_templates
  FOR EACH ROW EXECUTE FUNCTION update_notification_templates_updated_at();

CREATE TRIGGER trg_notification_template_versions_updated_at
  BEFORE UPDATE ON notification_template_versions
  FOR EACH ROW EXECUTE FUNCTION update_notification_templates_updated_at();