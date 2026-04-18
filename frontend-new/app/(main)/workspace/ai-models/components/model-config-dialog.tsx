'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Box, Button, Flex, Text } from '@radix-ui/themes';
import { MaterialIcon } from '@/app/components/ui/MaterialIcon';
import { WorkspaceRightPanel } from '@/app/(main)/workspace/components/workspace-right-panel';
import { SchemaFormField } from '@/app/(main)/workspace/connectors/components/schema-form-field';
import type { SchemaField } from '@/app/(main)/workspace/connectors/types';
import type { AIModelProvider, AIModelProviderField, ConfiguredModel } from '../types';
import { CAPABILITY_TO_MODEL_TYPE, CAPABILITY_DISPLAY_NAMES } from '../types';
import { AIModelsApi } from '../api';

const AI_MODELS_DOCS_URL = 'https://docs.pipeshub.com/ai-models/overview';

const CARD_STYLE: React.CSSProperties = {
  backgroundColor: 'var(--olive-2)',
  border: '1px solid var(--olive-3)',
  borderRadius: 'var(--radius-2)',
  padding: 'var(--space-4)',
};

interface ModelConfigDialogProps {
  open: boolean;
  mode: 'add' | 'edit';
  provider: AIModelProvider | null;
  capability: string | null;
  editModel: ConfiguredModel | null;
  onClose: () => void;
  onSaved: () => void;
}

const FRIENDLY_FIELD_NAMES = new Set(['modelFriendlyName']);
const COMPAT_FIELD_NAMES = new Set(['isReasoning', 'isMultimodal']);

function partitionModelFields(fields: AIModelProviderField[]) {
  const friendly = fields.filter((f) => FRIENDLY_FIELD_NAMES.has(f.name));
  const compat = fields.filter((f) => COMPAT_FIELD_NAMES.has(f.name));
  const model = fields.filter(
    (f) => !FRIENDLY_FIELD_NAMES.has(f.name) && !COMPAT_FIELD_NAMES.has(f.name)
  );
  return { friendlyFields: friendly, modelFields: model, compatFields: compat };
}

export function ModelConfigDialog({
  open,
  mode,
  provider,
  capability,
  editModel,
  onClose,
  onSaved,
}: ModelConfigDialogProps) {
  const [fields, setFields] = useState<AIModelProviderField[]>([]);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [iconError, setIconError] = useState(false);

  const { friendlyFields, modelFields, compatFields } = useMemo(
    () => partitionModelFields(fields),
    [fields]
  );

  useEffect(() => {
    setIconError(false);
  }, [provider?.providerId, open]);

  useEffect(() => {
    if (!open || !provider || !capability) {
      setFields([]);
      setValues({});
      setError(null);
      return;
    }

    const capFields = provider.fields[capability] ?? [];
    setFields(capFields as AIModelProviderField[]);

    if (mode === 'edit' && editModel) {
      const initial: Record<string, unknown> = {};
      for (const f of capFields) {
        const field = f as AIModelProviderField;
        if (field.name in (editModel.configuration ?? {})) {
          initial[field.name] = (editModel.configuration as Record<string, unknown>)[field.name];
        } else if (field.name === 'isMultimodal') {
          initial[field.name] = editModel.isMultimodal ?? field.defaultValue;
        } else if (field.name === 'isReasoning') {
          initial[field.name] = editModel.isReasoning ?? field.defaultValue;
        } else if (field.name === 'contextLength') {
          initial[field.name] = editModel.contextLength ?? field.defaultValue;
        } else if (field.name === 'modelFriendlyName') {
          initial[field.name] = editModel.modelFriendlyName ?? '';
        } else {
          initial[field.name] = field.defaultValue ?? '';
        }
      }
      setValues(initial);
    } else {
      const defaults: Record<string, unknown> = {};
      for (const f of capFields) {
        const field = f as AIModelProviderField;
        defaults[field.name] = field.defaultValue ?? '';
      }
      setValues(defaults);
    }
  }, [open, provider, capability, mode, editModel]);

  const handleFieldChange = useCallback((name: string, value: unknown) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  }, []);

  const handleSave = async () => {
    if (!provider || !capability) return;
    setError(null);
    setSaving(true);

    try {
      const modelType = CAPABILITY_TO_MODEL_TYPE[capability];
      if (!modelType) throw new Error(`Unknown capability: ${capability}`);

      const topLevelKeys = ['isMultimodal', 'isReasoning', 'contextLength'];
      const configuration: Record<string, unknown> = {};
      const topLevel: Record<string, unknown> = {};

      for (const [key, val] of Object.entries(values)) {
        if (topLevelKeys.includes(key)) {
          topLevel[key] = val;
        } else {
          configuration[key] = val;
        }
      }

      if (mode === 'add') {
        await AIModelsApi.addProvider({
          modelType,
          provider: provider.providerId,
          configuration,
          isMultimodal: (topLevel.isMultimodal as boolean) ?? false,
          isReasoning: (topLevel.isReasoning as boolean) ?? false,
          contextLength: topLevel.contextLength ? Number(topLevel.contextLength) : null,
        });
      } else if (editModel) {
        await AIModelsApi.updateProvider(modelType, editModel.modelKey, {
          provider: provider.providerId,
          configuration,
          isMultimodal: (topLevel.isMultimodal as boolean) ?? false,
          isReasoning: (topLevel.isReasoning as boolean) ?? false,
          contextLength: topLevel.contextLength ? Number(topLevel.contextLength) : null,
        });
      }

      onSaved();
      onClose();
    } catch (err: any) {
      const msg =
        err?.response?.data?.error?.message ??
        err?.response?.data?.message ??
        err?.message ??
        'Failed to save model configuration';
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const capLabel = capability ? (CAPABILITY_DISPLAY_NAMES[capability] ?? capability) : '';
  const title = `${mode === 'add' ? 'Add' : 'Edit'} ${provider?.name ?? ''} ${capLabel}`.trim();

  const documentationAction = (
    <Button
      variant="outline"
      color="gray"
      size="1"
      style={{ cursor: 'pointer', gap: 4 }}
      onClick={() => window.open(AI_MODELS_DOCS_URL, '_blank')}
    >
      <MaterialIcon name="open_in_new" size={14} color="var(--slate-11)" />
      Documentation
    </Button>
  );

  const headerIcon =
    provider && !iconError ? (
      <Flex
        align="center"
        justify="center"
        style={{ width: 20, height: 20, flexShrink: 0 }}
      >
        <img
          src={provider.iconPath}
          alt={provider.name}
          width={16}
          height={16}
          onError={() => setIconError(true)}
          style={{ display: 'block', objectFit: 'contain' }}
        />
      </Flex>
    ) : (
      <MaterialIcon name="smart_toy" size={20} color="var(--slate-12)" />
    );

  const renderFieldList = (list: AIModelProviderField[]) =>
    list.map((field) => (
      <SchemaFormField
        key={field.name}
        field={toSchemaField(field)}
        value={values[field.name]}
        onChange={handleFieldChange}
        disabled={saving}
      />
    ));

  const sectionHeading = (label: string) => (
    <Text size="2" weight="medium" style={{ color: 'var(--slate-12)' }}>
      {label}
    </Text>
  );

  return (
    <WorkspaceRightPanel
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={title}
      icon={headerIcon}
      headerActions={documentationAction}
      primaryLabel={mode === 'add' ? 'Add Model' : 'Update Model'}
      secondaryLabel="Cancel"
      primaryLoading={saving}
      onPrimaryClick={() => void handleSave()}
      onSecondaryClick={onClose}
    >
      <Flex direction="column" gap="4">
        <Box style={CARD_STYLE}>
          <Flex align="start" gap="2">
            <MaterialIcon
              name="info"
              size={18}
              color="var(--accent-11)"
              style={{ flexShrink: 0, marginTop: 1 }}
            />
            <Text size="2" style={{ color: 'var(--slate-11)', lineHeight: 1.5 }}>
              Configure your model to enable AI capabilities. Enter your provider credentials and
              choose options below. Use a clear instance name where asked—it is shown across
              Pipeshub when this model is used.
            </Text>
          </Flex>
        </Box>

        {fields.length === 0 ? (
          <Text size="2" style={{ color: 'var(--gray-10)', padding: 8 }}>
            No configuration required for this provider.
          </Text>
        ) : (
          <Flex direction="column" gap="4">
            {friendlyFields.length > 0 && (
              <Box style={CARD_STYLE}>
                <Flex direction="column" gap="3">
                  {sectionHeading('Model configuration')}
                  <Flex direction="column" gap="3">
                    {renderFieldList(friendlyFields)}
                  </Flex>
                </Flex>
              </Box>
            )}

            {modelFields.length > 0 && (
              <Box style={CARD_STYLE}>
                <Flex direction="column" gap="3">
                  {sectionHeading('Model configuration')}
                  <Flex direction="column" gap="3">
                    {renderFieldList(modelFields)}
                  </Flex>
                </Flex>
              </Box>
            )}

            {compatFields.length > 0 && (
              <Box style={CARD_STYLE}>
                <Flex direction="column" gap="3">
                  {sectionHeading('Model compatibilities')}
                  <Flex direction="column" gap="3">
                    {renderFieldList(compatFields)}
                  </Flex>
                </Flex>
              </Box>
            )}
          </Flex>
        )}

        {error && (
          <Text size="2" style={{ color: 'var(--red-11)', padding: '4px 0' }}>
            {error}
          </Text>
        )}
      </Flex>
    </WorkspaceRightPanel>
  );
}

/**
 * Convert our registry field type to the SchemaField shape expected by SchemaFormField.
 */
function toSchemaField(field: AIModelProviderField): SchemaField {
  return {
    name: field.name,
    displayName: field.displayName,
    fieldType: field.fieldType as any,
    required: field.required,
    defaultValue: field.defaultValue,
    placeholder: field.placeholder,
    description: field.description,
    isSecret: field.isSecret,
    options: field.options?.map((o) => ({ id: o.value, label: o.label })),
    validation: field.validation as any,
  };
}
