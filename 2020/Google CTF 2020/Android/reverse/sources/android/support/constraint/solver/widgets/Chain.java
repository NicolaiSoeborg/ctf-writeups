package android.support.constraint.solver.widgets;

import android.support.constraint.solver.ArrayRow;
import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.SolverVariable;
import android.support.constraint.solver.widgets.ConstraintWidget;
import java.util.ArrayList;

class Chain {
    private static final boolean DEBUG = false;

    Chain() {
    }

    static void applyChainConstraints(ConstraintWidgetContainer constraintWidgetContainer, LinearSystem system, int orientation) {
        ChainHead[] chainsArray;
        int chainsSize;
        int offset;
        if (orientation == 0) {
            offset = 0;
            chainsSize = constraintWidgetContainer.mHorizontalChainsSize;
            chainsArray = constraintWidgetContainer.mHorizontalChainsArray;
        } else {
            offset = 2;
            chainsSize = constraintWidgetContainer.mVerticalChainsSize;
            chainsArray = constraintWidgetContainer.mVerticalChainsArray;
        }
        for (int i = 0; i < chainsSize; i++) {
            ChainHead first = chainsArray[i];
            first.define();
            if (!constraintWidgetContainer.optimizeFor(4)) {
                applyChainConstraints(constraintWidgetContainer, system, orientation, offset, first);
            } else if (!Optimizer.applyChainOptimized(constraintWidgetContainer, system, orientation, offset, first)) {
                applyChainConstraints(constraintWidgetContainer, system, orientation, offset, first);
            }
        }
    }

    /* JADX INFO: Multiple debug info for r2v32 'beginNextAnchor'  android.support.constraint.solver.widgets.ConstraintAnchor: [D('beginNext' android.support.constraint.solver.SolverVariable), D('beginNextAnchor' android.support.constraint.solver.widgets.ConstraintAnchor)] */
    /* JADX INFO: Multiple debug info for r3v40 android.support.constraint.solver.SolverVariable: [D('beginNext' android.support.constraint.solver.SolverVariable), D('beginNextTarget' android.support.constraint.solver.SolverVariable)] */
    /* JADX INFO: Multiple debug info for r4v28 android.support.constraint.solver.ArrayRow: [D('lastMatch' android.support.constraint.solver.widgets.ConstraintWidget), D('row' android.support.constraint.solver.ArrayRow)] */
    /* JADX WARNING: Removed duplicated region for block: B:284:0x061c A[ADDED_TO_REGION] */
    /* JADX WARNING: Removed duplicated region for block: B:287:0x0625  */
    /* JADX WARNING: Removed duplicated region for block: B:313:0x06a5  */
    static void applyChainConstraints(ConstraintWidgetContainer container, LinearSystem system, int orientation, int offset, ChainHead chainHead) {
        boolean isChainSpread;
        boolean isChainSpread2;
        boolean isChainPacked;
        ConstraintWidget widget;
        ConstraintWidget last;
        ConstraintWidget last2;
        LinearSystem linearSystem;
        ConstraintWidget lastVisibleWidget;
        ConstraintWidget widget2;
        ConstraintWidget firstVisibleWidget;
        ConstraintWidget last3;
        ConstraintAnchor end;
        ConstraintAnchor endTarget;
        ConstraintWidget previousVisibleWidget;
        ConstraintWidget next;
        ConstraintWidget widget3;
        SolverVariable beginNext;
        SolverVariable beginNextTarget;
        ConstraintAnchor beginNextAnchor;
        ConstraintWidget next2;
        ConstraintWidget firstVisibleWidget2;
        ConstraintWidget last4;
        ConstraintWidget previousVisibleWidget2;
        ConstraintWidget next3;
        ConstraintWidget last5;
        SolverVariable beginNextTarget2;
        SolverVariable beginNext2;
        ConstraintAnchor beginNextAnchor2;
        ConstraintWidget lastVisibleWidget2;
        ConstraintWidget widget4;
        ConstraintWidget firstVisibleWidget3;
        float bias;
        int count;
        ArrayList<ConstraintWidget> listMatchConstraints;
        ConstraintWidget widget5;
        int count2;
        float currentWeight;
        ConstraintWidget firstMatchConstraintsWidget;
        float totalWeights;
        ConstraintWidget next4;
        int margin;
        ConstraintWidget first = chainHead.mFirst;
        ConstraintWidget last6 = chainHead.mLast;
        ConstraintWidget firstVisibleWidget4 = chainHead.mFirstVisibleWidget;
        ConstraintWidget lastVisibleWidget3 = chainHead.mLastVisibleWidget;
        ConstraintWidget head = chainHead.mHead;
        float totalWeights2 = chainHead.mTotalWeight;
        ConstraintWidget firstMatchConstraintsWidget2 = chainHead.mFirstMatchConstraintWidget;
        ConstraintWidget previousMatchConstraintsWidget = chainHead.mLastMatchConstraintWidget;
        boolean done = false;
        boolean isWrapContent = container.mListDimensionBehaviors[orientation] == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
        if (orientation == 0) {
            boolean isChainSpread3 = head.mHorizontalChainStyle == 0;
            isChainSpread2 = head.mHorizontalChainStyle == 1;
            isChainPacked = head.mHorizontalChainStyle == 2;
            widget = first;
            isChainSpread = isChainSpread3;
        } else {
            isChainSpread = head.mVerticalChainStyle == 0;
            isChainSpread2 = head.mVerticalChainStyle == 1;
            isChainPacked = head.mVerticalChainStyle == 2;
            widget = first;
        }
        while (!done) {
            ConstraintAnchor begin = widget.mListAnchors[offset];
            int strength = 4;
            if (isWrapContent || isChainPacked) {
                strength = 1;
            }
            int margin2 = begin.getMargin();
            if (!(begin.mTarget == null || widget == first)) {
                margin2 += begin.mTarget.getMargin();
            }
            if (isChainPacked && widget != first && widget != firstVisibleWidget4) {
                strength = 6;
            } else if (isChainSpread && isWrapContent) {
                strength = 4;
            }
            if (begin.mTarget != null) {
                if (widget == firstVisibleWidget4) {
                    totalWeights = totalWeights2;
                    firstMatchConstraintsWidget = firstMatchConstraintsWidget2;
                    system.addGreaterThan(begin.mSolverVariable, begin.mTarget.mSolverVariable, margin2, 5);
                } else {
                    totalWeights = totalWeights2;
                    firstMatchConstraintsWidget = firstMatchConstraintsWidget2;
                    system.addGreaterThan(begin.mSolverVariable, begin.mTarget.mSolverVariable, margin2, 6);
                }
                system.addEquality(begin.mSolverVariable, begin.mTarget.mSolverVariable, margin2, strength);
            } else {
                totalWeights = totalWeights2;
                firstMatchConstraintsWidget = firstMatchConstraintsWidget2;
            }
            if (isWrapContent) {
                if (widget.getVisibility() == 8 || widget.mListDimensionBehaviors[orientation] != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                    margin = 0;
                } else {
                    margin = 0;
                    system.addGreaterThan(widget.mListAnchors[offset + 1].mSolverVariable, widget.mListAnchors[offset].mSolverVariable, 0, 5);
                }
                system.addGreaterThan(widget.mListAnchors[offset].mSolverVariable, container.mListAnchors[offset].mSolverVariable, margin, 6);
            }
            ConstraintAnchor nextAnchor = widget.mListAnchors[offset + 1].mTarget;
            if (nextAnchor != null) {
                next4 = nextAnchor.mOwner;
                if (next4.mListAnchors[offset].mTarget == null || next4.mListAnchors[offset].mTarget.mOwner != widget) {
                    next4 = null;
                }
            } else {
                next4 = null;
            }
            if (next4 != null) {
                widget = next4;
            } else {
                done = true;
            }
            previousMatchConstraintsWidget = previousMatchConstraintsWidget;
            totalWeights2 = totalWeights;
            firstMatchConstraintsWidget2 = firstMatchConstraintsWidget;
        }
        float totalWeights3 = totalWeights2;
        if (lastVisibleWidget3 != null && last6.mListAnchors[offset + 1].mTarget != null) {
            ConstraintAnchor end2 = lastVisibleWidget3.mListAnchors[offset + 1];
            system.addLowerThan(end2.mSolverVariable, last6.mListAnchors[offset + 1].mTarget.mSolverVariable, -end2.getMargin(), 5);
        }
        if (isWrapContent) {
            system.addGreaterThan(container.mListAnchors[offset + 1].mSolverVariable, last6.mListAnchors[offset + 1].mSolverVariable, last6.mListAnchors[offset + 1].getMargin(), 6);
        }
        ArrayList<ConstraintWidget> listMatchConstraints2 = chainHead.mWeightedMatchConstraintsWidgets;
        if (listMatchConstraints2 != null && (count = listMatchConstraints2.size()) > 1) {
            ConstraintWidget lastMatch = null;
            float lastWeight = 0.0f;
            if (chainHead.mHasUndefinedWeights && !chainHead.mHasComplexMatchWeights) {
                totalWeights3 = (float) chainHead.mWidgetsMatchCount;
            }
            int i = 0;
            while (i < count) {
                ConstraintWidget match = listMatchConstraints2.get(i);
                float currentWeight2 = match.mWeight[orientation];
                if (currentWeight2 >= 0.0f) {
                    currentWeight = currentWeight2;
                    count2 = count;
                    widget5 = widget;
                    listMatchConstraints = listMatchConstraints2;
                } else if (chainHead.mHasComplexMatchWeights) {
                    count2 = count;
                    widget5 = widget;
                    listMatchConstraints = listMatchConstraints2;
                    system.addEquality(match.mListAnchors[offset + 1].mSolverVariable, match.mListAnchors[offset].mSolverVariable, 0, 4);
                    i++;
                    count = count2;
                    widget = widget5;
                    listMatchConstraints2 = listMatchConstraints;
                } else {
                    count2 = count;
                    widget5 = widget;
                    listMatchConstraints = listMatchConstraints2;
                    currentWeight = 1.0f;
                }
                if (currentWeight == 0.0f) {
                    system.addEquality(match.mListAnchors[offset + 1].mSolverVariable, match.mListAnchors[offset].mSolverVariable, 0, 6);
                } else {
                    if (lastMatch != null) {
                        SolverVariable begin2 = lastMatch.mListAnchors[offset].mSolverVariable;
                        SolverVariable end3 = lastMatch.mListAnchors[offset + 1].mSolverVariable;
                        SolverVariable nextBegin = match.mListAnchors[offset].mSolverVariable;
                        SolverVariable nextEnd = match.mListAnchors[offset + 1].mSolverVariable;
                        ArrayRow row = system.createRow();
                        row.createRowEqualMatchDimensions(lastWeight, totalWeights3, currentWeight, begin2, end3, nextBegin, nextEnd);
                        system.addConstraint(row);
                    }
                    lastMatch = match;
                    lastWeight = currentWeight;
                }
                i++;
                count = count2;
                widget = widget5;
                listMatchConstraints2 = listMatchConstraints;
            }
        }
        if (firstVisibleWidget4 == null) {
            lastVisibleWidget2 = lastVisibleWidget3;
            firstVisibleWidget = firstVisibleWidget4;
            widget4 = widget;
        } else if (firstVisibleWidget4 == lastVisibleWidget3 || isChainPacked) {
            ConstraintAnchor begin3 = first.mListAnchors[offset];
            ConstraintAnchor end4 = last6.mListAnchors[offset + 1];
            SolverVariable beginTarget = first.mListAnchors[offset].mTarget != null ? first.mListAnchors[offset].mTarget.mSolverVariable : null;
            SolverVariable endTarget2 = last6.mListAnchors[offset + 1].mTarget != null ? last6.mListAnchors[offset + 1].mTarget.mSolverVariable : null;
            if (firstVisibleWidget4 == lastVisibleWidget3) {
                begin3 = firstVisibleWidget4.mListAnchors[offset];
                end4 = firstVisibleWidget4.mListAnchors[offset + 1];
            }
            if (beginTarget == null || endTarget2 == null) {
                lastVisibleWidget = lastVisibleWidget3;
                firstVisibleWidget3 = firstVisibleWidget4;
                widget2 = widget;
            } else {
                if (orientation == 0) {
                    bias = head.mHorizontalBiasPercent;
                } else {
                    bias = head.mVerticalBiasPercent;
                }
                widget2 = widget;
                lastVisibleWidget = lastVisibleWidget3;
                firstVisibleWidget3 = firstVisibleWidget4;
                system.addCentering(begin3.mSolverVariable, beginTarget, begin3.getMargin(), bias, endTarget2, end4.mSolverVariable, end4.getMargin(), 5);
            }
            last3 = last6;
            last2 = firstVisibleWidget3;
            linearSystem = system;
            if (isChainSpread && !isChainSpread2) {
                return;
            }
            if (last2 != null) {
                ConstraintAnchor begin4 = last2.mListAnchors[offset];
                ConstraintAnchor end5 = lastVisibleWidget.mListAnchors[offset + 1];
                SolverVariable beginTarget2 = begin4.mTarget != null ? begin4.mTarget.mSolverVariable : null;
                SolverVariable endTarget3 = end5.mTarget != null ? end5.mTarget.mSolverVariable : null;
                if (last != lastVisibleWidget) {
                    ConstraintAnchor realEnd = last.mListAnchors[offset + 1];
                    endTarget3 = realEnd.mTarget != null ? realEnd.mTarget.mSolverVariable : null;
                }
                if (last2 == lastVisibleWidget) {
                    begin4 = last2.mListAnchors[offset];
                    end5 = last2.mListAnchors[offset + 1];
                }
                if (beginTarget2 != null && endTarget3 != null) {
                    int beginMargin = begin4.getMargin();
                    if (lastVisibleWidget == null) {
                        lastVisibleWidget = last;
                    }
                    linearSystem.addCentering(begin4.mSolverVariable, beginTarget2, beginMargin, 0.5f, endTarget3, end5.mSolverVariable, lastVisibleWidget.mListAnchors[offset + 1].getMargin(), 5);
                    return;
                }
                return;
            }
            return;
        } else {
            lastVisibleWidget2 = lastVisibleWidget3;
            firstVisibleWidget = firstVisibleWidget4;
            widget4 = widget;
        }
        if (!isChainSpread || firstVisibleWidget == null) {
            linearSystem = system;
            if (isChainSpread2) {
                last2 = firstVisibleWidget;
                if (last2 != null) {
                    boolean applyFixedEquality = chainHead.mWidgetsMatchCount > 0 && chainHead.mWidgetsCount == chainHead.mWidgetsMatchCount;
                    ConstraintWidget previousVisibleWidget3 = last2;
                    for (ConstraintWidget widget6 = last2; widget6 != null; widget6 = next) {
                        ConstraintWidget next5 = widget6.mNextChainWidget[orientation];
                        while (next5 != null && next5.getVisibility() == 8) {
                            next5 = next5.mNextChainWidget[orientation];
                        }
                        if (widget6 == last2 || widget6 == lastVisibleWidget || next5 == null) {
                            previousVisibleWidget = previousVisibleWidget3;
                            widget3 = widget6;
                            next = next5;
                        } else {
                            if (next5 == lastVisibleWidget) {
                                next5 = null;
                            }
                            ConstraintAnchor beginAnchor = widget6.mListAnchors[offset];
                            SolverVariable begin5 = beginAnchor.mSolverVariable;
                            if (beginAnchor.mTarget != null) {
                                SolverVariable solverVariable = beginAnchor.mTarget.mSolverVariable;
                            }
                            SolverVariable beginTarget3 = previousVisibleWidget3.mListAnchors[offset + 1].mSolverVariable;
                            int beginMargin2 = beginAnchor.getMargin();
                            int nextMargin = widget6.mListAnchors[offset + 1].getMargin();
                            if (next5 != null) {
                                beginNextAnchor = next5.mListAnchors[offset];
                                SolverVariable beginNextTarget3 = beginNextAnchor.mSolverVariable;
                                beginNextTarget = beginNextAnchor.mTarget != null ? beginNextAnchor.mTarget.mSolverVariable : null;
                                beginNext = beginNextTarget3;
                            } else {
                                beginNext = null;
                                beginNextAnchor = widget6.mListAnchors[offset + 1].mTarget;
                                if (beginNextAnchor != null) {
                                    beginNext = beginNextAnchor.mSolverVariable;
                                }
                                beginNextTarget = widget6.mListAnchors[offset + 1].mSolverVariable;
                            }
                            if (beginNextAnchor != null) {
                                nextMargin += beginNextAnchor.getMargin();
                            }
                            if (previousVisibleWidget3 != null) {
                                beginMargin2 += previousVisibleWidget3.mListAnchors[offset + 1].getMargin();
                            }
                            int strength2 = 4;
                            if (applyFixedEquality) {
                                strength2 = 6;
                            }
                            if (begin5 == null || beginTarget3 == null || beginNext == null || beginNextTarget == null) {
                                next2 = next5;
                                previousVisibleWidget = previousVisibleWidget3;
                                widget3 = widget6;
                            } else {
                                next2 = next5;
                                previousVisibleWidget = previousVisibleWidget3;
                                widget3 = widget6;
                                linearSystem.addCentering(begin5, beginTarget3, beginMargin2, 0.5f, beginNext, beginNextTarget, nextMargin, strength2);
                            }
                            next = next2;
                        }
                        previousVisibleWidget3 = widget3.getVisibility() != 8 ? widget3 : previousVisibleWidget;
                    }
                    ConstraintAnchor begin6 = last2.mListAnchors[offset];
                    ConstraintAnchor beginTarget4 = first.mListAnchors[offset].mTarget;
                    ConstraintAnchor end6 = lastVisibleWidget.mListAnchors[offset + 1];
                    ConstraintAnchor endTarget4 = last6.mListAnchors[offset + 1].mTarget;
                    if (beginTarget4 != null) {
                        if (last2 != lastVisibleWidget) {
                            linearSystem.addEquality(begin6.mSolverVariable, beginTarget4.mSolverVariable, begin6.getMargin(), 5);
                            endTarget = endTarget4;
                            last = last6;
                            end = end6;
                        } else if (endTarget4 != null) {
                            endTarget = endTarget4;
                            last = last6;
                            end = end6;
                            linearSystem.addCentering(begin6.mSolverVariable, beginTarget4.mSolverVariable, begin6.getMargin(), 0.5f, end6.mSolverVariable, endTarget4.mSolverVariable, end6.getMargin(), 5);
                        }
                        if (!(endTarget == null || last2 == lastVisibleWidget)) {
                            linearSystem.addEquality(end.mSolverVariable, endTarget.mSolverVariable, -end.getMargin(), 5);
                        }
                        if (isChainSpread) {
                        }
                        if (last2 != null) {
                        }
                    }
                    endTarget = endTarget4;
                    last = last6;
                    end = end6;
                    linearSystem.addEquality(end.mSolverVariable, endTarget.mSolverVariable, -end.getMargin(), 5);
                    if (isChainSpread) {
                    }
                    if (last2 != null) {
                    }
                } else {
                    last3 = last6;
                }
            } else {
                last3 = last6;
                last2 = firstVisibleWidget;
            }
            if (isChainSpread) {
            }
            if (last2 != null) {
            }
        } else {
            boolean applyFixedEquality2 = chainHead.mWidgetsMatchCount > 0 && chainHead.mWidgetsCount == chainHead.mWidgetsMatchCount;
            ConstraintWidget widget7 = firstVisibleWidget;
            ConstraintWidget previousVisibleWidget4 = firstVisibleWidget;
            while (widget7 != null) {
                ConstraintWidget next6 = widget7.mNextChainWidget[orientation];
                while (true) {
                    if (next6 != null) {
                        if (next6.getVisibility() != 8) {
                            break;
                        }
                        next6 = next6.mNextChainWidget[orientation];
                    } else {
                        break;
                    }
                }
                if (next6 != null || widget7 == lastVisibleWidget) {
                    ConstraintAnchor beginAnchor2 = widget7.mListAnchors[offset];
                    SolverVariable begin7 = beginAnchor2.mSolverVariable;
                    SolverVariable beginTarget5 = beginAnchor2.mTarget != null ? beginAnchor2.mTarget.mSolverVariable : null;
                    if (previousVisibleWidget4 != widget7) {
                        beginTarget5 = previousVisibleWidget4.mListAnchors[offset + 1].mSolverVariable;
                    } else if (widget7 == firstVisibleWidget && previousVisibleWidget4 == widget7) {
                        beginTarget5 = first.mListAnchors[offset].mTarget != null ? first.mListAnchors[offset].mTarget.mSolverVariable : null;
                    }
                    SolverVariable beginNext3 = null;
                    int beginMargin3 = beginAnchor2.getMargin();
                    int nextMargin2 = widget7.mListAnchors[offset + 1].getMargin();
                    if (next6 != null) {
                        ConstraintAnchor beginNextAnchor3 = next6.mListAnchors[offset];
                        SolverVariable beginNext4 = beginNextAnchor3.mSolverVariable;
                        beginNextTarget2 = widget7.mListAnchors[offset + 1].mSolverVariable;
                        beginNext2 = beginNext4;
                        beginNextAnchor2 = beginNextAnchor3;
                    } else {
                        ConstraintAnchor beginNextAnchor4 = last6.mListAnchors[offset + 1].mTarget;
                        if (beginNextAnchor4 != null) {
                            beginNext3 = beginNextAnchor4.mSolverVariable;
                        }
                        beginNextTarget2 = widget7.mListAnchors[offset + 1].mSolverVariable;
                        beginNext2 = beginNext3;
                        beginNextAnchor2 = beginNextAnchor4;
                    }
                    if (beginNextAnchor2 != null) {
                        nextMargin2 += beginNextAnchor2.getMargin();
                    }
                    if (previousVisibleWidget4 != null) {
                        beginMargin3 += previousVisibleWidget4.mListAnchors[offset + 1].getMargin();
                    }
                    if (begin7 == null || beginTarget5 == null || beginNext2 == null || beginNextTarget2 == null) {
                        next3 = next6;
                        previousVisibleWidget2 = previousVisibleWidget4;
                        firstVisibleWidget2 = firstVisibleWidget;
                        last4 = last6;
                        last5 = widget7;
                    } else {
                        int margin1 = beginMargin3;
                        if (widget7 == firstVisibleWidget) {
                            margin1 = firstVisibleWidget.mListAnchors[offset].getMargin();
                        }
                        int margin22 = nextMargin2;
                        if (widget7 == lastVisibleWidget) {
                            margin22 = lastVisibleWidget.mListAnchors[offset + 1].getMargin();
                        }
                        int strength3 = 4;
                        if (applyFixedEquality2) {
                            strength3 = 6;
                        }
                        last4 = last6;
                        firstVisibleWidget2 = firstVisibleWidget;
                        next3 = next6;
                        previousVisibleWidget2 = previousVisibleWidget4;
                        last5 = widget7;
                        system.addCentering(begin7, beginTarget5, margin1, 0.5f, beginNext2, beginNextTarget2, margin22, strength3);
                    }
                } else {
                    next3 = next6;
                    previousVisibleWidget2 = previousVisibleWidget4;
                    firstVisibleWidget2 = firstVisibleWidget;
                    last4 = last6;
                    last5 = widget7;
                }
                previousVisibleWidget4 = last5.getVisibility() != 8 ? last5 : previousVisibleWidget2;
                widget7 = next3;
                last6 = last4;
                firstVisibleWidget = firstVisibleWidget2;
            }
            linearSystem = system;
            last = last6;
            last2 = firstVisibleWidget;
            if (isChainSpread) {
            }
            if (last2 != null) {
            }
        }
    }
}
