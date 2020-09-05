package android.support.constraint.solver.widgets;

import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.widgets.ConstraintAnchor;
import android.support.constraint.solver.widgets.ConstraintWidget;
import com.google.ctf.sandbox.BuildConfig;
import java.util.ArrayList;

public class ConstraintTableLayout extends ConstraintWidgetContainer {
    public static final int ALIGN_CENTER = 0;
    private static final int ALIGN_FULL = 3;
    public static final int ALIGN_LEFT = 1;
    public static final int ALIGN_RIGHT = 2;
    private ArrayList<Guideline> mHorizontalGuidelines = new ArrayList<>();
    private ArrayList<HorizontalSlice> mHorizontalSlices = new ArrayList<>();
    private int mNumCols = 0;
    private int mNumRows = 0;
    private int mPadding = 8;
    private boolean mVerticalGrowth = true;
    private ArrayList<Guideline> mVerticalGuidelines = new ArrayList<>();
    private ArrayList<VerticalSlice> mVerticalSlices = new ArrayList<>();
    private LinearSystem system = null;

    class HorizontalSlice {
        ConstraintWidget bottom;
        int padding;
        ConstraintWidget top;

        HorizontalSlice() {
        }
    }

    class VerticalSlice {
        int alignment = 1;
        ConstraintWidget left;
        int padding;
        ConstraintWidget right;

        VerticalSlice() {
        }
    }

    public ConstraintTableLayout() {
    }

    public ConstraintTableLayout(int x, int y, int width, int height) {
        super(x, y, width, height);
    }

    public ConstraintTableLayout(int width, int height) {
        super(width, height);
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidgetContainer, android.support.constraint.solver.widgets.ConstraintWidget
    public String getType() {
        return "ConstraintTableLayout";
    }

    public int getNumRows() {
        return this.mNumRows;
    }

    public int getNumCols() {
        return this.mNumCols;
    }

    public int getPadding() {
        return this.mPadding;
    }

    public String getColumnsAlignmentRepresentation() {
        int numSlices = this.mVerticalSlices.size();
        String result = BuildConfig.FLAVOR;
        for (int i = 0; i < numSlices; i++) {
            VerticalSlice slice = this.mVerticalSlices.get(i);
            if (slice.alignment == 1) {
                result = result + "L";
            } else if (slice.alignment == 0) {
                result = result + "C";
            } else if (slice.alignment == 3) {
                result = result + "F";
            } else if (slice.alignment == 2) {
                result = result + "R";
            }
        }
        return result;
    }

    public String getColumnAlignmentRepresentation(int column) {
        VerticalSlice slice = this.mVerticalSlices.get(column);
        if (slice.alignment == 1) {
            return "L";
        }
        if (slice.alignment == 0) {
            return "C";
        }
        if (slice.alignment == 3) {
            return "F";
        }
        if (slice.alignment == 2) {
            return "R";
        }
        return "!";
    }

    public void setNumCols(int num) {
        if (this.mVerticalGrowth && this.mNumCols != num) {
            this.mNumCols = num;
            setVerticalSlices();
            setTableDimensions();
        }
    }

    public void setNumRows(int num) {
        if (!this.mVerticalGrowth && this.mNumCols != num) {
            this.mNumRows = num;
            setHorizontalSlices();
            setTableDimensions();
        }
    }

    public boolean isVerticalGrowth() {
        return this.mVerticalGrowth;
    }

    public void setVerticalGrowth(boolean value) {
        this.mVerticalGrowth = value;
    }

    public void setPadding(int padding) {
        if (padding > 1) {
            this.mPadding = padding;
        }
    }

    public void setColumnAlignment(int column, int alignment) {
        if (column < this.mVerticalSlices.size()) {
            this.mVerticalSlices.get(column).alignment = alignment;
            setChildrenConnections();
        }
    }

    public void cycleColumnAlignment(int column) {
        VerticalSlice slice = this.mVerticalSlices.get(column);
        switch (slice.alignment) {
            case 0:
                slice.alignment = 2;
                break;
            case 1:
                slice.alignment = 0;
                break;
            case 2:
                slice.alignment = 1;
                break;
        }
        setChildrenConnections();
    }

    public void setColumnAlignment(String alignment) {
        int n = alignment.length();
        for (int i = 0; i < n; i++) {
            char c = alignment.charAt(i);
            if (c == 'L') {
                setColumnAlignment(i, 1);
            } else if (c == 'C') {
                setColumnAlignment(i, 0);
            } else if (c == 'F') {
                setColumnAlignment(i, 3);
            } else if (c == 'R') {
                setColumnAlignment(i, 2);
            } else {
                setColumnAlignment(i, 0);
            }
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidgetContainer
    public ArrayList<Guideline> getVerticalGuidelines() {
        return this.mVerticalGuidelines;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidgetContainer
    public ArrayList<Guideline> getHorizontalGuidelines() {
        return this.mHorizontalGuidelines;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void addToSolver(LinearSystem system2) {
        super.addToSolver(system2);
        int count = this.mChildren.size();
        if (count != 0) {
            setTableDimensions();
            if (system2 == this.mSystem) {
                int num = this.mVerticalGuidelines.size();
                int i = 0;
                while (true) {
                    boolean z = true;
                    if (i >= num) {
                        break;
                    }
                    Guideline guideline = this.mVerticalGuidelines.get(i);
                    if (getHorizontalDimensionBehaviour() != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                        z = false;
                    }
                    guideline.setPositionRelaxed(z);
                    guideline.addToSolver(system2);
                    i++;
                }
                int num2 = this.mHorizontalGuidelines.size();
                for (int i2 = 0; i2 < num2; i2++) {
                    Guideline guideline2 = this.mHorizontalGuidelines.get(i2);
                    guideline2.setPositionRelaxed(getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT);
                    guideline2.addToSolver(system2);
                }
                for (int i3 = 0; i3 < count; i3++) {
                    ((ConstraintWidget) this.mChildren.get(i3)).addToSolver(system2);
                }
            }
        }
    }

    public void setTableDimensions() {
        int extra = 0;
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            extra += ((ConstraintWidget) this.mChildren.get(i)).getContainerItemSkip();
        }
        int count2 = count + extra;
        if (this.mVerticalGrowth) {
            if (this.mNumCols == 0) {
                setNumCols(1);
            }
            int rows = count2 / this.mNumCols;
            if (this.mNumCols * rows < count2) {
                rows++;
            }
            if (this.mNumRows != rows || this.mVerticalGuidelines.size() != this.mNumCols - 1) {
                this.mNumRows = rows;
                setHorizontalSlices();
            } else {
                return;
            }
        } else {
            if (this.mNumRows == 0) {
                setNumRows(1);
            }
            int cols = count2 / this.mNumRows;
            if (this.mNumRows * cols < count2) {
                cols++;
            }
            if (this.mNumCols != cols || this.mHorizontalGuidelines.size() != this.mNumRows - 1) {
                this.mNumCols = cols;
                setVerticalSlices();
            } else {
                return;
            }
        }
        setChildrenConnections();
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void setDebugSolverName(LinearSystem s, String name) {
        this.system = s;
        super.setDebugSolverName(s, name);
        updateDebugSolverNames();
    }

    private void updateDebugSolverNames() {
        if (this.system != null) {
            int num = this.mVerticalGuidelines.size();
            for (int i = 0; i < num; i++) {
                this.mVerticalGuidelines.get(i).setDebugSolverName(this.system, getDebugName() + ".VG" + i);
            }
            int num2 = this.mHorizontalGuidelines.size();
            for (int i2 = 0; i2 < num2; i2++) {
                this.mHorizontalGuidelines.get(i2).setDebugSolverName(this.system, getDebugName() + ".HG" + i2);
            }
        }
    }

    private void setVerticalSlices() {
        this.mVerticalSlices.clear();
        ConstraintWidget previous = this;
        float increment = 100.0f / ((float) this.mNumCols);
        float percent = increment;
        for (int i = 0; i < this.mNumCols; i++) {
            VerticalSlice slice = new VerticalSlice();
            slice.left = previous;
            if (i < this.mNumCols - 1) {
                Guideline guideline = new Guideline();
                guideline.setOrientation(1);
                guideline.setParent(this);
                guideline.setGuidePercent((int) percent);
                percent += increment;
                slice.right = guideline;
                this.mVerticalGuidelines.add(guideline);
            } else {
                slice.right = this;
            }
            previous = slice.right;
            this.mVerticalSlices.add(slice);
        }
        updateDebugSolverNames();
    }

    private void setHorizontalSlices() {
        this.mHorizontalSlices.clear();
        float increment = 100.0f / ((float) this.mNumRows);
        ConstraintWidget previous = this;
        float percent = increment;
        for (int i = 0; i < this.mNumRows; i++) {
            HorizontalSlice slice = new HorizontalSlice();
            slice.top = previous;
            if (i < this.mNumRows - 1) {
                Guideline guideline = new Guideline();
                guideline.setOrientation(0);
                guideline.setParent(this);
                guideline.setGuidePercent((int) percent);
                percent += increment;
                slice.bottom = guideline;
                this.mHorizontalGuidelines.add(guideline);
            } else {
                slice.bottom = this;
            }
            previous = slice.bottom;
            this.mHorizontalSlices.add(slice);
        }
        updateDebugSolverNames();
    }

    private void setChildrenConnections() {
        int count = this.mChildren.size();
        int index = 0;
        for (int i = 0; i < count; i++) {
            ConstraintWidget target = (ConstraintWidget) this.mChildren.get(i);
            int index2 = index + target.getContainerItemSkip();
            HorizontalSlice horizontalSlice = this.mHorizontalSlices.get(index2 / this.mNumCols);
            VerticalSlice verticalSlice = this.mVerticalSlices.get(index2 % this.mNumCols);
            ConstraintWidget targetLeft = verticalSlice.left;
            ConstraintWidget targetRight = verticalSlice.right;
            ConstraintWidget targetTop = horizontalSlice.top;
            ConstraintWidget targetBottom = horizontalSlice.bottom;
            target.getAnchor(ConstraintAnchor.Type.LEFT).connect(targetLeft.getAnchor(ConstraintAnchor.Type.LEFT), this.mPadding);
            if (targetRight instanceof Guideline) {
                target.getAnchor(ConstraintAnchor.Type.RIGHT).connect(targetRight.getAnchor(ConstraintAnchor.Type.LEFT), this.mPadding);
            } else {
                target.getAnchor(ConstraintAnchor.Type.RIGHT).connect(targetRight.getAnchor(ConstraintAnchor.Type.RIGHT), this.mPadding);
            }
            switch (verticalSlice.alignment) {
                case 1:
                    target.getAnchor(ConstraintAnchor.Type.LEFT).setStrength(ConstraintAnchor.Strength.STRONG);
                    target.getAnchor(ConstraintAnchor.Type.RIGHT).setStrength(ConstraintAnchor.Strength.WEAK);
                    break;
                case 2:
                    target.getAnchor(ConstraintAnchor.Type.LEFT).setStrength(ConstraintAnchor.Strength.WEAK);
                    target.getAnchor(ConstraintAnchor.Type.RIGHT).setStrength(ConstraintAnchor.Strength.STRONG);
                    break;
                case 3:
                    target.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT);
                    break;
            }
            target.getAnchor(ConstraintAnchor.Type.TOP).connect(targetTop.getAnchor(ConstraintAnchor.Type.TOP), this.mPadding);
            if (targetBottom instanceof Guideline) {
                target.getAnchor(ConstraintAnchor.Type.BOTTOM).connect(targetBottom.getAnchor(ConstraintAnchor.Type.TOP), this.mPadding);
            } else {
                target.getAnchor(ConstraintAnchor.Type.BOTTOM).connect(targetBottom.getAnchor(ConstraintAnchor.Type.BOTTOM), this.mPadding);
            }
            index = index2 + 1;
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void updateFromSolver(LinearSystem system2) {
        super.updateFromSolver(system2);
        if (system2 == this.mSystem) {
            int num = this.mVerticalGuidelines.size();
            for (int i = 0; i < num; i++) {
                this.mVerticalGuidelines.get(i).updateFromSolver(system2);
            }
            int num2 = this.mHorizontalGuidelines.size();
            for (int i2 = 0; i2 < num2; i2++) {
                this.mHorizontalGuidelines.get(i2).updateFromSolver(system2);
            }
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidgetContainer
    public boolean handlesInternalConstraints() {
        return true;
    }

    public void computeGuidelinesPercentPositions() {
        int num = this.mVerticalGuidelines.size();
        for (int i = 0; i < num; i++) {
            this.mVerticalGuidelines.get(i).inferRelativePercentPosition();
        }
        int num2 = this.mHorizontalGuidelines.size();
        for (int i2 = 0; i2 < num2; i2++) {
            this.mHorizontalGuidelines.get(i2).inferRelativePercentPosition();
        }
    }
}
