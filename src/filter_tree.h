/**
 *
 * @file: filter_tree.h
 * @date: 16.04.2023
 */

#ifndef IPK_PROJECT_2_FILTER_TREE_H
#define IPK_PROJECT_2_FILTER_TREE_H

#include <vector>
#include <string>

enum FILTER_TREE_TYPE {
    FILTER_TREE_TYPE_ROOT,
    FILTER_TREE_TYPE_AND,
    FILTER_TREE_TYPE_OR,
    FILTER_TREE_TYPE_NOT,
    FILTER_TREE_TYPE_FILTER
};

class FilterTree {
private:
    FILTER_TREE_TYPE type;
    std::string *filter = nullptr;
    std::vector<FilterTree *> *children = nullptr;

    std::string process_current_node();

public:
    explicit FilterTree(FILTER_TREE_TYPE type);

    explicit FilterTree(std::string *filter);

    FilterTree(FILTER_TREE_TYPE type, std::string *filter);

    ~FilterTree();

    void add_child(FilterTree *child);

    [[nodiscard]] std::vector<FilterTree *> *get_children() const;

    [[nodiscard]] FILTER_TREE_TYPE get_type() const;

    [[nodiscard]] std::string *get_filter() const;

    std::string generate_filter();
};

#endif// IPK_PROJECT_2_FILTER_TREE_H
