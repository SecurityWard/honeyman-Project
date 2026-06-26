import { useState, useRef, useEffect } from 'react';
import './DateRangeSelector.css';

export type DateRangePreset = 'all' | '24h' | '7d' | '30d' | '90d' | 'custom';

export interface DateRange {
  preset: DateRangePreset;
  startDate?: Date;
  endDate?: Date;
}

interface DateRangeSelectorProps {
  value: DateRange;
  onChange: (range: DateRange) => void;
}

export default function DateRangeSelector({ value, onChange }: DateRangeSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [showCustom, setShowCustom] = useState(false);
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);

  const presets = [
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
    { value: '90d', label: 'Last 90 Days' },
    { value: 'all', label: 'All Time' },
    { value: 'custom', label: 'Custom Range' },
  ];

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handlePresetChange = (preset: DateRangePreset) => {
    if (preset === 'custom') {
      setShowCustom(true);
      setIsOpen(false);
      return;
    }

    onChange({ preset });
    setIsOpen(false);
  };

  const handleCustomApply = () => {
    if (customStart && customEnd) {
      onChange({
        preset: 'custom',
        startDate: new Date(customStart),
        endDate: new Date(customEnd),
      });
      setShowCustom(false);
    }
  };

  const getDisplayText = () => {
    if (value.preset === 'custom' && value.startDate && value.endDate) {
      return `${value.startDate.toLocaleDateString()} - ${value.endDate.toLocaleDateString()}`;
    }
    return presets.find(p => p.value === value.preset)?.label || 'Select Range';
  };

  return (
    <div className="date-range-selector">
      <span className="date-range-label">Time Range:</span>
      <div className="date-range-dropdown" ref={dropdownRef}>
        <button
          className="date-range-button"
          onClick={() => setIsOpen(!isOpen)}
        >
          {getDisplayText()}
          <span className="dropdown-arrow">▼</span>
        </button>
        {isOpen && (
          <div className="date-range-menu">
            {presets.map(preset => (
              <button
                key={preset.value}
                className={`preset-option ${value.preset === preset.value ? 'active' : ''}`}
                onClick={() => handlePresetChange(preset.value as DateRangePreset)}
              >
                {preset.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {showCustom && (
        <div className="custom-range-modal" onClick={() => setShowCustom(false)}>
          <div className="custom-range-content" onClick={(e) => e.stopPropagation()}>
            <h3>Custom Date Range</h3>
            <div className="date-inputs">
              <div className="date-input-group">
                <label>Start Date</label>
                <input
                  type="date"
                  value={customStart}
                  onChange={(e) => setCustomStart(e.target.value)}
                  max={customEnd || new Date().toISOString().split('T')[0]}
                />
              </div>
              <div className="date-input-group">
                <label>End Date</label>
                <input
                  type="date"
                  value={customEnd}
                  onChange={(e) => setCustomEnd(e.target.value)}
                  min={customStart}
                  max={new Date().toISOString().split('T')[0]}
                />
              </div>
            </div>
            <div className="custom-range-actions">
              <button className="btn-cancel" onClick={() => setShowCustom(false)}>
                Cancel
              </button>
              <button
                className="btn-apply"
                onClick={handleCustomApply}
                disabled={!customStart || !customEnd}
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
