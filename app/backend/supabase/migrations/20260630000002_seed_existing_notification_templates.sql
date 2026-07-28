-- Seed existing hardcoded notification templates into the new versioning system
-- This migration populates the notification_templates and notification_template_versions
-- tables with the templates currently defined in template.service.ts

-- First, insert the base templates
INSERT INTO notification_templates (event_type, name, description) VALUES
('EscrowDeposited', 'Escrow Deposited', 'Notification sent when escrow is deposited'),
('payment.received', 'Payment Received', 'Notification sent when a payment is received'),
('EscrowWithdrawn', 'Escrow Withdrawn', 'Notification sent when escrow is withdrawn'),
('EscrowRefunded', 'Escrow Refunded', 'Notification sent when escrow is refunded'),
('username.claimed', 'Username Claimed', 'Notification sent when a username is claimed'),
('recurring.payment.due', 'Recurring Payment Due', 'Notification sent when a recurring payment is due'),
('recurring.payment.executed', 'Recurring Payment Executed', 'Notification sent when a recurring payment executes'),
('recurring.payment.failed', 'Recurring Payment Failed', 'Notification sent when a recurring payment fails'),
('recurring.payment.cancelled', 'Recurring Payment Cancelled', 'Notification sent when a recurring payment is cancelled'),
('recurring.link.created', 'Recurring Link Created', 'Notification sent when a recurring link is created'),
('recurring.link.updated', 'Recurring Link Updated', 'Notification sent when a recurring link is updated'),
('recurring.link.paused', 'Recurring Link Paused', 'Notification sent when a recurring link is paused'),
('recurring.link.resumed', 'Recurring Link Resumed', 'Notification sent when a recurring link is resumed'),
('recurring.link.completed', 'Recurring Link Completed', 'Notification sent when a recurring link is completed')
ON CONFLICT (event_type) DO NOTHING;

-- Now insert version 1 (active) for each template
INSERT INTO notification_template_versions (template_id, version_number, title, body, status, change_notes, created_by)
SELECT 
  nt.id,
  1 as version_number,
  CASE nt.event_type
    WHEN 'EscrowDeposited' THEN 'Escrow Deposit'
    WHEN 'payment.received' THEN 'Payment Received'
    WHEN 'EscrowWithdrawn' THEN 'Escrow Withdrawn'
    WHEN 'EscrowRefunded' THEN 'Escrow Refunded'
    WHEN 'username.claimed' THEN 'Username Claimed'
    WHEN 'recurring.payment.due' THEN 'Payment Due'
    WHEN 'recurring.payment.executed' THEN 'Payment Executed'
    WHEN 'recurring.payment.failed' THEN 'Payment Failed'
    WHEN 'recurring.payment.cancelled' THEN 'Payment Cancelled'
    WHEN 'recurring.link.created' THEN 'Link Created'
    WHEN 'recurring.link.updated' THEN 'Link Updated'
    WHEN 'recurring.link.paused' THEN 'Link Paused'
    WHEN 'recurring.link.resumed' THEN 'Link Resumed'
    WHEN 'recurring.link.completed' THEN 'Link Completed'
  END as title,
  CASE nt.event_type
    WHEN 'EscrowDeposited' THEN 'You deposited {{amountStroops}} into escrow.'
    WHEN 'payment.received' THEN 'You received {{amountStroops}} from {{sender}}.'
    WHEN 'EscrowWithdrawn' THEN 'You withdrew {{amountStroops}} from escrow.'
    WHEN 'EscrowRefunded' THEN 'You received a refund of {{amountStroops}}.'
    WHEN 'username.claimed' THEN 'Your username {{username}} is now active.'
    WHEN 'recurring.payment.due' THEN 'A recurring payment of {{amount}} {{asset}} is due.'
    WHEN 'recurring.payment.executed' THEN 'Recurring payment of {{amount}} {{asset}} executed.'
    WHEN 'recurring.payment.failed' THEN 'Recurring payment of {{amount}} {{asset}} failed.'
    WHEN 'recurring.payment.cancelled' THEN 'Recurring payment cancelled.'
    WHEN 'recurring.link.created' THEN 'New recurring link created.'
    WHEN 'recurring.link.updated' THEN 'Recurring link updated.'
    WHEN 'recurring.link.paused' THEN 'Recurring link paused.'
    WHEN 'recurring.link.resumed' THEN 'Recurring link resumed.'
    WHEN 'recurring.link.completed' THEN 'Recurring link completed.'
  END as body,
  'active' as status,
  'Initial version seeded from existing hardcoded templates' as change_notes,
  'system' as created_by
FROM notification_templates nt
WHERE NOT EXISTS (
  SELECT 1 FROM notification_template_versions tv WHERE tv.template_id = nt.id
);