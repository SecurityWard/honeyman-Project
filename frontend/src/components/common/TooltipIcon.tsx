import './TooltipIcon.css';

interface TooltipIconProps {
  text: string;
}

export default function TooltipIcon({ text }: TooltipIconProps) {
  return (
    <div className="tooltip-icon">
      <span className="info-icon">ⓘ</span>
      <div className="tooltip-content">{text}</div>
    </div>
  );
}
