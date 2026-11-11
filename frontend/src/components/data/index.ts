/**
 * Shared data-display components (design system layer 2). Import from "@/components/data".
 * Primitives and status badges live in "@/components/ui".
 */
export { EntityLink, type EntityLinkProps } from "./EntityLink";
export { ENTITY_META, ENTITY_TYPES, entityHref, entityTypeLabel, isEntityType, provenanceHref, type EntityMeta, type EntityType, type ProvenanceScope } from "./entityRoutes";

export { JsonView, type JsonViewProps } from "./JsonView";
export { CodeBlock, type CodeBlockProps } from "./CodeBlock";
export { CopyButton, copyText, type CopyButtonProps } from "./CopyButton";
export { RedactedText, RedactionMarker, isRedactedValue, REDACTION_EXPLANATION, REDACTION_PREFIX } from "./Redacted";

export { Timeline, type TimelineItem, type TimelineProps } from "./Timeline";
export { EvidenceList, type EvidenceItem, type EvidenceListProps } from "./EvidenceList";

export { FilterBar, FilterSelect, type FilterBarProps, type FilterOption, type FilterSelectProps } from "./FilterBar";
export { SearchInput, type SearchInputProps } from "./SearchInput";
export { SegmentedControl, type SegmentOption, type SegmentedControlProps } from "./SegmentedControl";
export { Pagination, type PaginationProps } from "./Pagination";
export { DataTable, type DataTableColumn, type DataTableProps } from "./DataTable";
export { compareValues, nextSort, sortRows, type SortDirection, type SortState, type SortValue } from "./sorting";

export { TimeSeriesChart, type TimeSeries, type TimeSeriesChartProps, type TimeSeriesDatum } from "./charts/TimeSeriesChart";
export { BarList, type BarListItem, type BarListProps } from "./charts/BarList";
export { DonutChart, type DonutChartProps, type DonutDatum } from "./charts/DonutChart";
export { Sparkline, type SparklineProps } from "./charts/Sparkline";
export { ChartTooltipCard, seriesColor, toneColor, type TooltipRow } from "./charts/chartTheme";

export { RiskMeter, riskLevelFromScore, type RiskLevel, type RiskMeterProps } from "./RiskMeter";
export { ScoreRing, gradeFromScore, type ScoreRingProps } from "./ScoreRing";
export { ConfirmDialog, type ConfirmDialogProps } from "./ConfirmDialog";
export { Markdown, type MarkdownProps } from "./markdown/Markdown";
export { parseMarkdown, parseInline, safeHref, type Block as MarkdownBlock, type Inline as MarkdownInline } from "./markdown/parse";
export { Section, InlineStat, type InlineStatProps, type SectionProps } from "./Section";
